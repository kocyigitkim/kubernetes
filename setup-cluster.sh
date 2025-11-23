#!/usr/bin/env bash

###############################################################################
# Kubernetes + Calico + Longhorn Kurulum Scripti (Ubuntu, kubeadm)
#
# Özellikler:
# - Ubuntu 22.04/24.04 için optimize
# - containerd runtime (SystemdCgroup = true)
# - kubeadm ile control-plane kurulumu (kubelet + kubectl)
# - Calico CNI kurulumu
# - Longhorn dağıtık storage kurulumu
#
# Davranış:
# - Her adım idempotent: ilgili bileşen zaten kuruluysa tekrar kurmaz
# - Her kurulum sonrası temel sağlık kontrolleri yapılır
# - Otomatik taint yönetimi:
#     * Cluster'da tek node varsa control-plane taint kaldırılır (single-node)
#     * Birden fazla node varsa taint'ler korunur
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
POD_NETWORK_CIDR="${POD_NETWORK_CIDR:-192.168.0.0/16}"    # Calico ile uyumlu
CALICO_MANIFEST_URL="${CALICO_MANIFEST_URL:-https://raw.githubusercontent.com/projectcalico/calico/v3.31.1/manifests/calico.yaml}"
LONGHORN_MANIFEST_URL="${LONGHORN_MANIFEST_URL:-https://raw.githubusercontent.com/longhorn/longhorn/v1.10.1/deploy/longhorn.yaml}"

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
        die "Bu script root olarak çalıştırılmalıdır. Örnek: sudo $0"
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

    systemctl enable --now kubelet >/dev/null 2>&1 || die "kubelet servisi başlatılamadı."

    if ! is_service_active kubelet; then
        die "kubelet servisi aktif değil."
    fi

    if ! command_exists kubeadm || ! command_exists kubectl; then
        die "kubeadm veya kubectl komutları bulunamadı."
    fi

    log_info "Kubernetes bileşenleri kuruldu ve kontrol edildi."
}

# -----------------------------------------------------------------------------
# Control-plane kurulumu (idempotent)
# -----------------------------------------------------------------------------
init_control_plane() {
    if [[ -f /etc/kubernetes/admin.conf ]]; then
        log_warn "/etc/kubernetes/admin.conf bulundu. kubeadm init atlanıyor (cluster zaten init edilmiş)."
        return
    fi

    log_info "Kubernetes control-plane başlatılıyor (kubeadm init)..."
    local hostname
    hostname="$(hostname)"

    kubeadm init \
        --pod-network-cidr="${POD_NETWORK_CIDR}" \
        --node-name="${hostname}" || die "kubeadm init başarısız oldu."

    if [[ ! -f /etc/kubernetes/admin.conf ]]; then
        die "kubeadm init sonrası admin.conf bulunamadı."
    fi

    log_info "kubeadm init başarıyla tamamlandı."
}

configure_kubectl() {
    log_info "kubectl için kubeconfig ayarlanıyor..."

    export KUBECONFIG=/etc/kubernetes/admin.conf

    # root
    mkdir -p /root/.kube
    cp -f /etc/kubernetes/admin.conf /root/.kube/config
    chown root:root /root/.kube/config

    # sudo ile çağıran kullanıcı
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        local user_home
        user_home="$(eval echo ~"${SUDO_USER}")"

        mkdir -p "${user_home}/.kube"
        cp -f /etc/kubernetes/admin.conf "${user_home}/.kube/config"
        chown -R "${SUDO_USER}:${SUDO_USER}" "${user_home}/.kube"
        log_info "kubectl config ${SUDO_USER} kullanıcısına da kopyalandı."
    fi

    if ! kubectl version --short >/dev/null 2>&1; then
        die "kubectl cluster'a bağlanamıyor. /etc/kubernetes/admin.conf'u kontrol et."
    fi

    log_info "kubectl yapılandırması başarılı."
}

wait_for_control_plane() {
    log_info "kube-apiserver hazır olana kadar bekleniyor (max 300s)..."
    if ! kubectl wait --for=condition=Ready pod \
        -l component=kube-apiserver -n kube-system --timeout=300s >/dev/null 2>&1; then
        log_warn "kube-apiserver ready bekleme süresi doldu. Mevcut podlar:"
        kubectl get pods -n kube-system -o wide || true
    else
        log_info "kube-apiserver hazır."
    fi
}

wait_for_nodes_ready() {
    log_info "Node'ların Ready olmasını bekleniyor (max 600s)..."
    if ! kubectl wait --for=condition=Ready node --all --timeout=600s >/dev/null 2>&1; then
        log_warn "Node'lar tamamen Ready olmadı. Mevcut durum:"
        kubectl get nodes -o wide || true
    else
        log_info "Tüm node'lar Ready durumda."
    fi
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
# CNI: Calico kurulumu (idempotent)
# -----------------------------------------------------------------------------
install_calico_cni() {
    log_info "Calico CNI kurulumu kontrol ediliyor..."

    if kubectl get daemonset calico-node -n kube-system >/dev/null 2>&1; then
        log_info "Calico (calico-node DS) zaten mevcut. Kurulum atlanıyor."
        return
    fi

    log_info "Calico CNI kuruluyor..."
    kubectl apply -f "${CALICO_MANIFEST_URL}" || die "Calico manifest uygulanamadı."

    log_info "Calico daemonset rollout durumu bekleniyor (max 300s)..."
    if ! kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s >/dev/null 2>&1; then
        log_warn "Calico daemonset tam olarak hazır değil. Pod durumlarını kontrol edin:"
        kubectl -n kube-system get pods -l k8s-app=calico-node -o wide || true
    else
        log_info "Calico daemonset hazır."
    fi
}

# -----------------------------------------------------------------------------
# Longhorn kurulumu (idempotent)
# -----------------------------------------------------------------------------
install_longhorn() {
    log_info "Longhorn kurulumu kontrol ediliyor..."

    if kubectl get ns longhorn-system >/dev/null 2>&1; then
        log_info "longhorn-system namespace zaten mevcut. Longhorn kurulumu atlanıyor."
        return
    fi

    # prereq check
    check_longhorn_prereqs

    log_info "Longhorn manifest uygulanıyor..."
    kubectl apply -f "${LONGHORN_MANIFEST_URL}" || die "Longhorn manifest uygulanamadı."

    log_info "Longhorn namespace oluşturuldu, pod'lar ayağa kalkıyor."
    log_info "Longhorn UI deployment için hazır bekleniyor (max 600s)..."

    if ! kubectl -n longhorn-system wait --for=condition=Available deployment/longhorn-ui --timeout=600s >/dev/null 2>&1; then
        log_warn "Longhorn UI deployment henüz fully Available değil. Detay için:"
        kubectl -n longhorn-system get pods -o wide || true
    else
        log_info "Longhorn UI deployment hazır."
    fi
}

# -----------------------------------------------------------------------------
# Otomatik taint yönetimi
# -----------------------------------------------------------------------------
auto_manage_taints() {
    log_info "Node taint yapısı otomatik yönetiliyor..."

    local node_count
    node_count="$(kubectl get nodes -o json | jq '.items | length')"

    if [[ "${node_count}" -eq 0 ]]; then
        log_warn "Hiç node bulunamadı, taint yönetimi atlanıyor."
        return
    fi

    if [[ "${node_count}" -eq 1 ]]; then
        log_info "Tek node tespit edildi (single-node cluster). control-plane taint kaldırılıyor..."
        kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true
        kubectl taint nodes --all node-role.kubernetes.io/master- >/dev/null 2>&1 || true
    else
        log_info "Birden fazla node var. control-plane taint'leri korunuyor."
    fi

    log_info "Güncel taint listesi:"
    kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints --no-headers || true
}

# -----------------------------------------------------------------------------
# Kubectl kolaylıkları
# -----------------------------------------------------------------------------
enable_kubectl_completion() {
    log_info "kubectl bash completion ve alias ayarlanıyor..."

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
}

print_summary() {
    echo
    log_info "==============================================="
    log_info " Kubernetes + Calico + Longhorn kurulumu bitti"
    log_info "==============================================="
    echo

    log_info "Cluster bilgisi:"
    kubectl cluster-info || true
    echo

    log_info "Node durumu:"
    kubectl get nodes -o wide || true
    echo

    log_info "Calico pod'ları:"
    kubectl -n kube-system get pods -l k8s-app=calico-node -o wide || true
    echo

    log_info "Longhorn pod'ları:"
    kubectl -n longhorn-system get pods -o wide 2>/dev/null || log_warn "Longhorn pod'ları henüz görünmüyor."
    echo

    log_info "Worker node eklemek için kubeadm join komutu (varsa):"
    kubeadm token create --print-join-command 2>/dev/null || log_warn "kubeadm join komutu üretilemedi (cluster tam hazır olmayabilir)."
    echo

    log_info "Yararlı komutlar:"
    echo "  kubectl get nodes"
    echo "  kubectl get pods -A"
    echo "  kubectl -n longhorn-system get pods"
    echo "  kubectl get pods -A -w"
    echo
    log_info "Yeni shell'de alias ve completion için: source ~/.bashrc"
}

# -----------------------------------------------------------------------------
# Ana akış
# -----------------------------------------------------------------------------
main() {
    require_root
    check_os

    log_info "Kubernetes + Calico + Longhorn kurulum akışı başlıyor..."

    update_system
    install_base_packages
    disable_swap
    configure_kernel_modules
    configure_sysctl
    install_containerd
    add_kubernetes_repo
    install_kubernetes_components

    init_control_plane
    configure_kubectl
    wait_for_control_plane

    # --- Kubernetes ayağa kalktıktan SONRA ek bileşenler ---
    install_calico_cni
    wait_for_nodes_ready
    auto_manage_taints
    install_longhorn
    # --------------------------------------------------------

    enable_kubectl_completion
    print_summary
}

main "$@"
