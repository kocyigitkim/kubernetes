#!/usr/bin/env bash

###############################################################################
# Kubernetes Worker Node Setup Script (Ubuntu, kubeadm)
#
# Özellikler:
# - Ubuntu 22.04/24.04 için optimize
# - containerd runtime (SystemdCgroup = true)
# - kubeadm + kubelet (+ opsiyonel kubectl) kurulumu
# - Longhorn için gerekli temel paketler ve kernel ayarları (her node için)
#
# Davranış:
# - Her adım idempotent: ilgili bileşen zaten kuruluysa tekrar kurmaz
# - Node daha önce cluster'a join olduysa join adımını atlar
# - Parametre olarak verilen kubeadm join komutunu çalıştırır
###############################################################################

set -euo pipefail

# -----------------------------------------------------------------------------
# Ayarlar (gerekirse env ile override edilebilir)
# -----------------------------------------------------------------------------
K8S_MINOR_VERSION="${K8S_MINOR_VERSION:-v1.34}"  # pkgs.k8s.io stable minor

# -----------------------------------------------------------------------------
# Renkler & log yardımcıları
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()       { log_error "$*"; exit 1; }

# -----------------------------------------------------------------------------
# Genel yardımcı fonksiyonlar
# -----------------------------------------------------------------------------
command_exists() { command -v "$1" >/dev/null 2>&1; }

is_service_active() {
    local svc="$1"
    systemctl is-active --quiet "$svc"
}

is_package_installed() {
    local pkg="$1"
    dpkg -l "$pkg" 2>/dev/null | awk 'NR>5 && $1=="ii" {print $2}' | grep -qx "$pkg"
}

# -----------------------------------------------------------------------------
# Ön kontroller
# -----------------------------------------------------------------------------
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Bu script root olarak çalıştırılmalıdır. Örnek: sudo $0 \"kubeadm join ...\""
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        die "/etc/os-release bulunamadı. Desteklenmeyen sistem."
    fi

    # shellcheck disable=SC1091
    . /etc/os-release

    if [[ "${ID}" != "ubuntu" ]]; then
        die "Bu script sadece Ubuntu için tasarlanmıştır. Mevcut: ${ID}"
    fi

    log_info "Dağıtım: ${PRETTY_NAME}"
}

# -----------------------------------------------------------------------------
# Sistem hazırlığı
# -----------------------------------------------------------------------------
update_system() {
    log_info "Sistem paketleri güncelleniyor..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    log_info "Sistem güncellemesi tamamlandı."
}

install_base_packages() {
    log_info "Temel paketler ve Longhorn prereq paketleri kuruluyor..."

    apt-get install -y -qq \
        apt-transport-https \
        ca-certificates \
        curl \
        wget \
        gpg \
        gnupg \
        lsb-release \
        software-properties-common \
        bash-completion \
        net-tools \
        jq \
        util-linux \
        lvm2 \
        cryptsetup-bin \
        conntrack \
        open-iscsi \
        nfs-common

    # iSCSI kernel modülü
    log_info "iscsi_tcp modülü yükleniyor..."
    echo "iscsi_tcp" >/etc/modules-load.d/iscsi-tcp.conf
    modprobe iscsi_tcp || log_warn "iscsi_tcp modülü yüklenemedi, manuel kontrol et."

    # open-iscsi + iscsid servisi
    log_info "iscsid servisi enable + start ediliyor..."
    systemctl enable --now iscsid >/dev/null 2>&1 || log_warn "iscsid servisi başlatılamadı, durumu kontrol et."
    systemctl enable --now open-iscsi >/dev/null 2>&1 || true

    log_info "Temel paketler ve Longhorn prereq paketleri kuruldu."
}

disable_swap() {
    log_info "Swap devre dışı bırakılıyor..."
    swapoff -a || true
    sed -i.bak '/\sswap\s/ s/^/#/' /etc/fstab || true
    log_info "Swap devre dışı bırakıldı."
}

configure_kernel_modules() {
    log_info "Kernel modülleri (overlay, br_netfilter, iscsi_tcp) ayarlanıyor..."
    cat <<EOF >/etc/modules-load.d/k8s.conf
overlay
br_netfilter
iscsi_tcp
EOF

    modprobe overlay || true
    modprobe br_netfilter || true
    modprobe iscsi_tcp || true
    log_info "Kernel modülleri ayarlandı."
}

configure_sysctl() {
    log_info "Sysctl ağ parametreleri ayarlanıyor..."
    cat <<EOF >/etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

    sysctl --system >/dev/null 2>&1
    log_info "Sysctl parametreleri uygulandı."
}

# -----------------------------------------------------------------------------
# containerd kurulumu (idempotent)
# -----------------------------------------------------------------------------
install_containerd() {
    if command_exists containerd; then
        log_info "containerd zaten kurulu. Konfigürasyon doğrulanacak."
    else
        log_info "containerd kuruluyor..."
        apt-get install -y -qq containerd || die "containerd kurulamadı."
    fi

    mkdir -p /etc/containerd

    if [[ ! -s /etc/containerd/config.toml ]]; then
        log_info "containerd varsayılan config oluşturuluyor..."
        containerd config default >/etc/containerd/config.toml
    fi

    if grep -q "SystemdCgroup = false" /etc/containerd/config.toml; then
        log_info "SystemdCgroup = true olacak şekilde containerd config güncelleniyor..."
        sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    else
        log_info "SystemdCgroup zaten true görünüyor."
    fi

    systemctl daemon-reload
    systemctl enable --now containerd >/dev/null 2>&1 || die "containerd servisi başlatılamadı."

    if ! is_service_active containerd; then
        die "containerd servisi aktif değil."
    fi

    log_info "containerd kurulumu ve kontrolü başarılı."
}

# -----------------------------------------------------------------------------
# Kubernetes repo & paketler (idempotent)
# -----------------------------------------------------------------------------
add_kubernetes_repo() {
    log_info "Kubernetes apt repository kontrol ediliyor..."

    mkdir -p /etc/apt/keyrings

    local repo_file="/etc/apt/sources.list.d/kubernetes.list"
    local repo_line="deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR_VERSION}/deb/ /"

    if [[ -f "${repo_file}" ]] && grep -q "${K8S_MINOR_VERSION}" "${repo_file}"; then
        log_info "Kubernetes repo (${K8S_MINOR_VERSION}) zaten tanımlı."
    else
        log_info "Kubernetes repo ekleniyor (${K8S_MINOR_VERSION})..."
        curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR_VERSION}/deb/Release.key" \
            | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

        echo "${repo_line}" > "${repo_file}"
    fi

    apt-get update -qq
    log_info "Kubernetes repo güncellendi."
}

install_kubernetes_components() {
    if is_package_installed kubelet && is_package_installed kubeadm && is_package_installed kubectl; then
        log_info "kubelet, kubeadm ve kubectl zaten kurulu."
        return
    fi

    log_info "kubelet, kubeadm, kubectl kuruluyor..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq kubelet kubeadm kubectl || die "Kubernetes paketleri kurulamadı."
    apt-mark hold kubelet kubeadm kubectl

    systemctl enable --now kubelet >/dev/null 2>&1 || die "kubelet servisi başlatılamadı."

    if ! is_service_active kubelet; then
        die "kubelet servisi aktif değil."
    fi

    if ! command_exists kubeadm; then
        die "kubeadm komutu bulunamadı."
    fi

    log_info "Kubernetes bileşenleri kuruldu ve kontrol edildi."
}

# -----------------------------------------------------------------------------
# Worker node join
# -----------------------------------------------------------------------------
join_cluster() {
    local join_cmd="$1"

    if [[ -z "${join_cmd}" ]]; then
        die "kubeadm join komutu parametre olarak verilmelidir. Örnek: $0 \"kubeadm join ...\""
    fi

    if [[ -f /etc/kubernetes/kubelet.conf ]]; then
        log_warn "/etc/kubernetes/kubelet.conf bulundu. Bu node büyük ihtimalle cluster'a zaten join olmuş. kubeadm join atlanıyor."
        return
    fi

    log_info "Bu node cluster'a join ediliyor..."
    log_info "Çalıştırılan komut: ${join_cmd}"

    # Temizlik: olası eski/yarım configler
    kubeadm reset -f || true

    # join komutunu çalıştır
    eval "${join_cmd}" || die "kubeadm join başarısız oldu."

    if [[ ! -f /etc/kubernetes/kubelet.conf ]]; then
        die "kubeadm join sonrası /etc/kubernetes/kubelet.conf bulunamadı. Join başarısız olabilir."
    fi

    # kubelet'in aktif olduğundan emin ol
    systemctl enable --now kubelet >/dev/null 2>&1 || die "kubelet servisi join sonrası başlatılamadı."

    if ! is_service_active kubelet; then
        die "kubelet servisi join sonrası aktif değil. journalctl -u kubelet ile logları kontrol et."
    fi

    log_info "Worker node başarılı şekilde cluster'a join oldu (lokal kontrol)."
}

print_summary() {
    echo
    log_info "======================================="
    log_info " Kubernetes Worker Node kurulumu bitti"
    log_info "======================================="
    echo

    log_info "Lokal servis durumu:"
    systemctl status kubelet --no-pager -l | sed -n '1,20p' || true
    echo

    log_info "Kontrol-plane tarafında node'u kontrol etmek için:"
    echo "  kubectl get nodes -o wide"
    echo
    log_info "Eğer node Ready değilse kubelet loglarını inceleyin:"
    echo "  journalctl -u kubelet -f"
    echo
}

# -----------------------------------------------------------------------------
# Ana akış
# -----------------------------------------------------------------------------
main() {
    local JOIN_COMMAND="${1:-}"

    require_root
    check_os

    log_info "Kubernetes Worker Node kurulum akışı başlıyor..."

    update_system
    install_base_packages
    disable_swap
    configure_kernel_modules
    configure_sysctl
    install_containerd
    add_kubernetes_repo
    install_kubernetes_components
    join_cluster "${JOIN_COMMAND}"
    print_summary
}

main "$@"
