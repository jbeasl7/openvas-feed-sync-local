# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1317");
  script_cve_id("CVE-2022-48987", "CVE-2024-43098", "CVE-2024-47794", "CVE-2024-49569", "CVE-2024-50210", "CVE-2024-53103", "CVE-2024-53135", "CVE-2024-53146", "CVE-2024-53157", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53179", "CVE-2024-53185", "CVE-2024-53187", "CVE-2024-53194", "CVE-2024-53195", "CVE-2024-53214", "CVE-2024-53219", "CVE-2024-53224", "CVE-2024-53685", "CVE-2024-54683", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56549", "CVE-2024-56569", "CVE-2024-56570", "CVE-2024-56572", "CVE-2024-56574", "CVE-2024-56583", "CVE-2024-56584", "CVE-2024-56587", "CVE-2024-56588", "CVE-2024-56592", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56606", "CVE-2024-56611", "CVE-2024-56614", "CVE-2024-56615", "CVE-2024-56623", "CVE-2024-56631", "CVE-2024-56633", "CVE-2024-56642", "CVE-2024-56647", "CVE-2024-56650", "CVE-2024-56658", "CVE-2024-56662", "CVE-2024-56664", "CVE-2024-56672", "CVE-2024-56688", "CVE-2024-56690", "CVE-2024-56703", "CVE-2024-56709", "CVE-2024-56716", "CVE-2024-56720", "CVE-2024-56722", "CVE-2024-56739", "CVE-2024-56747", "CVE-2024-56748", "CVE-2024-56751", "CVE-2024-56756", "CVE-2024-56763", "CVE-2024-56769", "CVE-2024-56770", "CVE-2024-56779", "CVE-2024-56780", "CVE-2024-57807", "CVE-2024-57874", "CVE-2024-57876", "CVE-2024-57883", "CVE-2024-57884", "CVE-2024-57888", "CVE-2024-57889", "CVE-2024-57924", "CVE-2024-57946", "CVE-2025-21649", "CVE-2025-21650", "CVE-2025-21656");
  script_tag(name:"creation_date", value:"2025-04-01 04:28:37 +0000 (Tue, 01 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-27 22:00:13 +0000 (Thu, 27 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1317)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1317");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1317");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1317 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"i3c: Use i3cdev->desc->info instead of calling i3c_device_get_info() to avoid deadlock(CVE-2024-43098)

KVM: arm64: Get rid of userspace_irqchip_in_use(CVE-2024-53195)

virtio-blk: don't keep queue frozen during system suspend(CVE-2024-57946)

workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker(CVE-2024-57888)

mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim().(CVE-2024-57884)

net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue(CVE-2025-21650)

ceph: give up on paths longer than PATH_MAX(CVE-2024-53685)

net: hns3: fix kernel crash when 1588 is sent on HIP08 devices(CVE-2025-21649)

drm/dp_mst: Fix resetting msg rx state after topology removal(CVE-2024-57876)

arm64: ptrace: fix partial SETREGSET for NT_ARM_TAGGED_ADDR_CTRL(CVE-2024-57874)

hwmon: (drivetemp) Fix driver producing garbage data when SCSI errors occur(CVE-2025-21656)

mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet(CVE-2024-55916)

netfilter: IDLETIMER: Fix for possible ABBA deadlock(CVE-2024-54683)

scsi: megaraid_sas: Fix for a potential deadlock(CVE-2024-57807)

bpf: Prevent tailcall infinite loop caused by freplace(CVE-2024-47794)

fs: relax assertions on failure to encode file handles(CVE-2024-57924)

media: platform: allegro-dvt: Fix possible memory leak in allocate_buffers_internal().(CVE-2024-56572)

net/sched: netem: account for backlog updates from child qdisc(CVE-2024-56770)

nvme-rdma: unquiesce admin_q before destroy it(CVE-2024-49569)

nfsd: fix nfs4_openowner leak when concurrent nfsd4_open occur(CVE-2024-56779)

netdevsim: prevent bad user input in nsim_dev_health_break_write().(CVE-2024-56716)

xsk: fix OOB map writes when deleting elements(CVE-2024-56614)

bpf, sockmap: Several fixes to bpf_msg_pop_data(CVE-2024-56720)

net: inet6: do not leave a dangling sk pointer in inet6_create().(CVE-2024-56600)

af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

NFSv4.0: Fix a use-after-free problem in the asynchronous open()(CVE-2024-53173)

pinctrl: mcp23s08: Fix sleeping in atomic context due to regmap locking(CVE-2024-57889)

drm/modes: Avoid divide by zero harder in drm_mode_vrefresh().(CVE-2024-56369)

scsi: hisi_sas: Create all dump files during debugfs initialization(CVE-2024-56588)

scsi: qla2xxx: Fix use after free on unload(CVE-2024-56623)

RDMA/hns: Fix cpu stuck caused by printings during reset(CVE-2024-56722)

bpf: Call free_htab_elem() after htab_unlock_bucket().(CVE-2024-56592)

ipv6: release nexthop on device removal(CVE-2024-56751)

scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb()(CVE-2024-56747)

NFSD: Prevent a potential integer overflow(CVE-2024-53146)

net: Fix icmp host relookup triggering ip_rt_bug(CVE-2024-56647)

hv_sock: Initializing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~182.0.0.95.h2572.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~182.0.0.95.h2572.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~182.0.0.95.h2572.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~182.0.0.95.h2572.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~182.0.0.95.h2572.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~182.0.0.95.h2572.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
