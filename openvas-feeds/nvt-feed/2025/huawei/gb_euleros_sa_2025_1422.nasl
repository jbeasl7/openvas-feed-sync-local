# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1422");
  script_cve_id("CVE-2022-48720", "CVE-2023-52923", "CVE-2024-47141", "CVE-2024-47794", "CVE-2024-47809", "CVE-2024-49569", "CVE-2024-53164", "CVE-2024-53168", "CVE-2024-53195", "CVE-2024-53217", "CVE-2024-53685", "CVE-2024-54683", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56568", "CVE-2024-56636", "CVE-2024-56637", "CVE-2024-56644", "CVE-2024-56769", "CVE-2024-57795", "CVE-2024-57798", "CVE-2024-57807", "CVE-2024-57874", "CVE-2024-57876", "CVE-2024-57883", "CVE-2024-57884", "CVE-2024-57888", "CVE-2024-57890", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57924", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57946", "CVE-2024-57947", "CVE-2025-21638", "CVE-2025-21640", "CVE-2025-21648", "CVE-2025-21649", "CVE-2025-21650", "CVE-2025-21651", "CVE-2025-21653", "CVE-2025-21665", "CVE-2025-21666", "CVE-2025-21667", "CVE-2025-21669", "CVE-2025-21682", "CVE-2025-21683", "CVE-2025-21694");
  script_tag(name:"creation_date", value:"2025-05-07 04:27:40 +0000 (Wed, 07 May 2025)");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-27 22:00:13 +0000 (Thu, 27 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1422)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1422");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1422");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1422 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"filemap: avoid truncating 64-bit offset to 32 bits(CVE-2025-21665)

iomap: avoid avoid truncating 64-bit offset to 32 bits(CVE-2025-21667)

fs/proc: fix softlockup in __read_vmcore (part 2).(CVE-2025-21694)

net: hns3: don't auto enable misc vector(CVE-2025-21651)

netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute(CVE-2025-21653)

netfilter: ipset: Hold module reference while requesting a module(CVE-2024-56637)

sctp: sysctl: auth_enable: avoid using current->nsproxy(CVE-2025-21638)

sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy(CVE-2025-21640)

af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK(CVE-2024-57901)

af_packet: fix vlan_get_tci() vs MSG_PEEK(CVE-2024-57902)

net: sched: fix ordering of qlen adjustment(CVE-2024-53164)

geneve: do not assume mac header is set in geneve_xmit_skb().(CVE-2024-56636)

RDMA/rxe: Remove the direct link to net_device(CVE-2024-57795)

net/ipv6: release expired exception dst cached in socket(CVE-2024-56644)

NFSD: Prevent NULL dereference in nfsd4_process_cb_update()(CVE-2024-53217)

iommu/arm-smmu: Defer probe of clients after smmu device bound(CVE-2024-56568)

net/sctp: Prevent autoclose integer overflow in sctp_association_init().(CVE-2024-57938)

dlm: fix possible lkb_resource null dereference(CVE-2024-47809)

vsock/virtio: discard packets if the transport changes(CVE-2025-21669)

vsock: prevent null-ptr-deref in vsock_*[has_data<pipe>has_space](CVE-2025-21666)

netfilter: nf_tables: adapt set backend to use GC transaction API(CVE-2023-52923)

RDMA/uverbs: Prevent integer overflow issue(CVE-2024-57890)

pinmux: Use sequential access to access desc->pinmux data(CVE-2024-47141)

drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req().(CVE-2024-57798)

selinux: ignore unknown extended permissions(CVE-2024-57931)

eth: bnxt: always recalculate features after XDP clearing, fix null-deref(CVE-2025-21682)

bpf: Fix bpf_sk_select_reuseport() memory leak(CVE-2025-21683)

net: restrict SO_REUSEPORT to inet sockets(CVE-2024-57903)

sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket(CVE-2024-53168)

net: macsec: Fix offload support for NETDEV_UNREGISTER event(CVE-2022-48720)

netfilter: nf_set_pipapo: fix initial map fill(CVE-2024-57947)

KVM: arm64: Get rid of userspace_irqchip_in_use(CVE-2024-53195)

virtio-blk: don't keep queue frozen during system suspend(CVE-2024-57946)

workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker(CVE-2024-57888)

mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim().(CVE-2024-57884)

net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue(CVE-2025-21650)

ceph: give up on paths longer than PATH_MAX(CVE-2024-53685)

net: hns3: fix kernel crash when 1588 is sent on HIP08 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2482.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2482.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2482.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2482.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2482.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2482.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
