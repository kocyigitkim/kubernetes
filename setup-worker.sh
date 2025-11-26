#!/usr/bin/env bash

###############################################################################
# Kubernetes Worker Node Kurulum Scripti (Ubuntu, kubeadm)
#
# Özellikler:
# - Ubuntu 22.04/24.04 için optimize
# - containerd runtime (SystemdCgroup = true)
# - kubeadm ile worker node kurulumu (kubelet + kubectl)
# - Longhorn için gerekli tüm prereq paketleri
#
# Kullanım:
#   sudo ./setup-worker.sh "kubeadm join <control-plane-ip>:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>"
#
# Davranış:
# - Her adım idempotent: ilgili bileşen zaten kuruluysa tekrar kurmaz
# - Longhorn için gerekli paketler:
#     * open-iscsi + iscsid (iscsiadm)
#     * nfs-common (NFSv4 client)
#     * jq, util-linux, lvm2, cryptsetup-bin, curl, wget, conntrack vb.
###############################################################################

set -euo pipefail

# -----------------------------------------------------------------------------
# Ayarlar (gerekirse env ile override edilebilir)
# -----------------------------------------------------------------------------
K8S_MINOR_VERSION="${K8S_MINOR_VERSION:-v1.34}"           # pkgs.k8s.io stable minor

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
        die "Bu script root olarak çalıştırılmalıdır. Örnek: sudo $0 \"<join-command>\""
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

check_join_command() {
    local join_cmd="$1"
    
    if [[ -z "${join_cmd}" ]]; then
        die "Kullanım: sudo $0 \"kubeadm join <control-plane-ip>:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>\""
    fi
    
    if [[ ! "${join_cmd}" =~ ^kubeadm[[:space:]]+join ]]; then
        die "Geçersiz join komutu. 'kubeadm join' ile başlamalıdır."
    fi
    
    log_info "Join komutu formatı geçerli."
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

    # Longhorn + Kubernetes için gerekenler:
    # - curl, wget, apt-transport-https, ca-certificates, gpg/gnupg, lsb-release
    # - jq, util-linux, lvm2, cryptsetup-bin, conntrack
    # - open-iscsi (iscsid), nfs-common
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

    # open-iscsi paketi iscsid servisini getiriyor
    log_info "iscsid servisi enable + start ediliyor..."
    systemctl enable --now iscsid >/dev/null 2>&1 || log_warn "iscsid servisi başlatılamadı, durumu kontrol et."

    # Longhorn NFS client
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

    systemctl enable --now kubelet >/dev/null 2>&1 || log_warn "kubelet servisi başlatılamadı (join öncesi normal)."

    if ! command_exists kubeadm || ! command_exists kubectl; then
        die "kubeadm veya kubectl komutları bulunamadı."
    fi

    log_info "Kubernetes bileşenleri kuruldu."
}

# -----------------------------------------------------------------------------
# Longhorn prereq health check
# -----------------------------------------------------------------------------
check_longhorn_prereqs() {
    log_info "Longhorn için gerekli paket ve servisler kontrol ediliyor..."

    local required_pkgs=(
        "open-iscsi"
        "nfs-common"
        "jq"
        "util-linux"
        "lvm2"
        "cryptsetup-bin"
    )

    for pkg in "${required_pkgs[@]}"; do
        if ! is_package_installed "${pkg}"; then
            die "Longhorn prereq paketi eksik: ${pkg} (install_base_packages fonksiyonunu kontrol et)."
        fi
    done

    if ! is_service_active iscsid; then
        die "iscsid servisi aktif değil. open-iscsi ve iscsid servis durumunu kontrol et."
    fi

    if ! command_exists iscsiadm; then
        die "iscsiadm komutu bulunamadı. open-iscsi kurulumu hatalı olabilir."
    fi

    if ! command_exists mount.nfs; then
        die "mount.nfs komutu bulunamadı. nfs-common kurulumu hatalı olabilir."
    fi

    log_info "Longhorn prereq kontrolleri başarılı."
}

# -----------------------------------------------------------------------------
# Worker node cluster'a katılım
# -----------------------------------------------------------------------------
join_cluster() {
    local join_cmd="$1"
    
    if [[ -f /etc/kubernetes/kubelet.conf ]]; then
        log_warn "/etc/kubernetes/kubelet.conf bulundu. Bu node zaten bir cluster'a katılmış görünüyor."
        log_warn "Yeniden katılmak için önce 'kubeadm reset' çalıştırın."
        return
    fi

    log_info "Worker node cluster'a katılıyor..."
    log_info "Join komutu: ${join_cmd}"
    
    eval "${join_cmd}" || die "kubeadm join komutu başarısız oldu."

    if [[ ! -f /etc/kubernetes/kubelet.conf ]]; then
        die "kubeadm join sonrası kubelet.conf bulunamadı."
    fi

    log_info "Worker node başarıyla cluster'a katıldı."
}

wait_for_kubelet() {
    log_info "kubelet servisinin aktif olması bekleniyor..."
    
    local max_wait=60
    local elapsed=0
    
    while ! is_service_active kubelet && [[ ${elapsed} -lt ${max_wait} ]]; do
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    if ! is_service_active kubelet; then
        log_warn "kubelet servisi ${max_wait}s içinde aktif olmadı. Servis durumu:"
        systemctl status kubelet --no-pager || true
    else
        log_info "kubelet servisi aktif."
    fi
}

# -----------------------------------------------------------------------------
# Kubectl kolaylıkları (opsiyonel - worker'da admin config olmayacak)
# -----------------------------------------------------------------------------
enable_kubectl_completion() {
    log_info "kubectl bash completion ve alias ayarlanıyor..."

    if command_exists kubectl; then
        kubectl completion bash >/etc/bash_completion.d/kubectl 2>/dev/null || true

        {
            echo 'alias k=kubectl'
            echo 'complete -o default -F __start_kubectl k'
        } >> /root/.bashrc

        if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
            local user_home
            user_home="$(eval echo ~"${SUDO_USER}")"
            {
                echo 'alias k=kubectl'
                echo 'complete -o default -F __start_kubectl k'
            } >> "${user_home}/.bashrc"
        fi

        log_info "kubectl alias ve completion ayarlandı."
    fi
}

print_summary() {
    echo
    log_info "=============================================="
    log_info " Worker Node kurulumu tamamlandı"
    log_info "=============================================="
    echo

    log_info "Node bilgisi:"
    echo "  Hostname: $(hostname)"
    echo "  IP: $(hostname -I | awk '{print $1}')"
    echo

    log_info "Servis durumları:"
    systemctl status kubelet --no-pager | head -n 3 || true
    systemctl status containerd --no-pager | head -n 3 || true
    systemctl status iscsid --no-pager | head -n 3 || true
    echo

    log_info "Longhorn prereq durumu:"
    check_longhorn_prereqs 2>/dev/null || log_warn "Longhorn prereq kontrolünde uyarı var."
    echo

    log_info "Control-plane'den node durumunu kontrol etmek için:"
    echo "  kubectl get nodes -o wide"
    echo "  kubectl get nodes $(hostname) -o yaml"
    echo
    
    log_info "Worker node üzerinde log kontrolleri:"
    echo "  journalctl -u kubelet -f"
    echo "  journalctl -u containerd -f"
    echo
    
    log_info "Yeni shell'de alias ve completion için: source ~/.bashrc"
}

# -----------------------------------------------------------------------------
# Ana akış
# -----------------------------------------------------------------------------
main() {
    local join_command="${1:-}"
    
    require_root
    check_os
    check_join_command "${join_command}"

    log_info "Kubernetes Worker Node kurulum akışı başlıyor..."

    update_system
    install_base_packages
    disable_swap
    configure_kernel_modules
    configure_sysctl
    install_containerd
    add_kubernetes_repo
    install_kubernetes_components
    check_longhorn_prereqs

    join_cluster "${join_command}"
    wait_for_kubelet

    enable_kubectl_completion
    print_summary
}

main "$@"
