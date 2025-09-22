# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2815");
  script_cve_id("CVE-2021-47024", "CVE-2021-47296", "CVE-2021-47391", "CVE-2021-47400", "CVE-2021-47423", "CVE-2021-47434", "CVE-2021-47496", "CVE-2022-48732", "CVE-2022-48788", "CVE-2022-48828", "CVE-2022-48850", "CVE-2022-48879", "CVE-2022-48899", "CVE-2022-48911", "CVE-2022-48912", "CVE-2022-48930", "CVE-2022-48943", "CVE-2023-52880", "CVE-2023-52885", "CVE-2023-52898", "CVE-2024-25739", "CVE-2024-26763", "CVE-2024-26852", "CVE-2024-26921", "CVE-2024-35950", "CVE-2024-36286", "CVE-2024-39494", "CVE-2024-39509", "CVE-2024-40959", "CVE-2024-40978", "CVE-2024-41012", "CVE-2024-41014", "CVE-2024-41020", "CVE-2024-41035", "CVE-2024-41044", "CVE-2024-41087", "CVE-2024-41095", "CVE-2024-42070", "CVE-2024-42084", "CVE-2024-42090", "CVE-2024-42102", "CVE-2024-42106", "CVE-2024-42131", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42154", "CVE-2024-42232", "CVE-2024-42244", "CVE-2024-42265", "CVE-2024-42285", "CVE-2024-42286", "CVE-2024-42289", "CVE-2024-42292", "CVE-2024-42304", "CVE-2024-42305", "CVE-2024-42312", "CVE-2024-43830", "CVE-2024-43853", "CVE-2024-43856", "CVE-2024-43861", "CVE-2024-43871", "CVE-2024-43882", "CVE-2024-43890", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43914", "CVE-2024-44944", "CVE-2024-44987", "CVE-2024-45006", "CVE-2024-46800");
  script_tag(name:"creation_date", value:"2024-11-11 04:32:03 +0000 (Mon, 11 Nov 2024)");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 17:18:55 +0000 (Fri, 20 Sep 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2815)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2815");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2815");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2815 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vsock/virtio: free queued packets when closing socket(CVE-2021-47024)

KVM: PPC: Fix kvm_arch_vcpu_ioctl vcpu_load leak(CVE-2021-47296)

kernel:RDMA/cma: Ensure rdma_addr_cancel() happens before issuing more requests(CVE-2021-47391)

net: hns3: do not allow call hns3_nic_net_open repeatedly(CVE-2021-47400)

drm/ nouveau/debugfs: fix file release memory leak(CVE-2021-47423)

xhci: Fix command ring pointer corruption while aborting a command(CVE-2021-47434)

net/tls: Fix flipped sign in tls_err_abort() calls(CVE-2021-47496)

drm/ nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

nvme-rdma: fix possible use-after-free in transport error_recovery work(CVE-2022-48788)

NFSD: Fix ia_size underflow(CVE-2022-48828)

net-sysfs: add check for netdevice being present to speed_show(CVE-2022-48850)

efi: fix NULL-deref in init error path(CVE-2022-48879)

drm/virtio: Fix GEM handle creation UAF(CVE-2022-48899)

netfilter: nf_queue: fix possible use-after-free(CVE-2022-48911)

netfilter: fix use-after-free in __nf_register_net_hook()(CVE-2022-48912)

RDMA/ib_srp: Fix a deadlock(CVE-2022-48930)

KVM: x86/mmu: make apf token non-zero to fix bug(CVE-2022-48943)

tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

SUNRPC: Fix UAF in svc_tcp_listen_data_ready()(CVE-2023-52885)

xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

create_empty_lvol in drivers/mtd/ubi/vtbl.c in the Linux kernel through 6.7.4 can attempt to allocate zero bytes, and crash, because of a missing check for ubi->leb_size.(CVE-2024-25739)

dm-crypt: don't modify the data when using authenticated encryption(CVE-2024-26763)

net/ipv6: avoid possible UAF in ip6_route_mpath_notify()(CVE-2024-26852)

inet: inet_defrag: prevent sk release while still in use(CVE-2024-26921)

drm/client: Fully protect modes[] with dev->mode_config.mutex(CVE-2024-35950)

netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu()(CVE-2024-36286)

kernel:ima: Fix use-after-free on a dentry's dname.name(CVE-2024-39494)

HID: core: remove unnecessary WARN_ON() in implement()(CVE-2024-39509)

xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

scsi: qedi: Fix crash while reading debugfs attribute(CVE-2024-40978)

filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

ppp: reject claimed-as-LCP but actually malformed packets(CVE-2024-41044)

ata: libata-core: Fix double free on error(CVE-2024-41087)

drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes(CVE-2024-41095)

netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h1380.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h1380.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h1380.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2103.1.0.h1380.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
