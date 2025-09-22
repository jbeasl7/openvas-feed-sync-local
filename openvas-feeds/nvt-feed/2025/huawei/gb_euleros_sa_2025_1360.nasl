# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1360");
  script_cve_id("CVE-2024-47141", "CVE-2024-47794", "CVE-2024-47809", "CVE-2024-49569", "CVE-2024-53093", "CVE-2024-53103", "CVE-2024-53124", "CVE-2024-53125", "CVE-2024-53135", "CVE-2024-53140", "CVE-2024-53146", "CVE-2024-53157", "CVE-2024-53164", "CVE-2024-53168", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53179", "CVE-2024-53185", "CVE-2024-53187", "CVE-2024-53194", "CVE-2024-53195", "CVE-2024-53214", "CVE-2024-53217", "CVE-2024-53219", "CVE-2024-53224", "CVE-2024-53685", "CVE-2024-54683", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56568", "CVE-2024-56569", "CVE-2024-56570", "CVE-2024-56574", "CVE-2024-56584", "CVE-2024-56587", "CVE-2024-56588", "CVE-2024-56592", "CVE-2024-56593", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56606", "CVE-2024-56608", "CVE-2024-56611", "CVE-2024-56614", "CVE-2024-56615", "CVE-2024-56623", "CVE-2024-56631", "CVE-2024-56633", "CVE-2024-56637", "CVE-2024-56642", "CVE-2024-56644", "CVE-2024-56647", "CVE-2024-56650", "CVE-2024-56658", "CVE-2024-56662", "CVE-2024-56664", "CVE-2024-56672", "CVE-2024-56688", "CVE-2024-56690", "CVE-2024-56694", "CVE-2024-56703", "CVE-2024-56709", "CVE-2024-56716", "CVE-2024-56720", "CVE-2024-56722", "CVE-2024-56739", "CVE-2024-56747", "CVE-2024-56748", "CVE-2024-56751", "CVE-2024-56756", "CVE-2024-56763", "CVE-2024-56769", "CVE-2024-56770", "CVE-2024-56779", "CVE-2024-56780", "CVE-2024-57795", "CVE-2024-57798", "CVE-2024-57807", "CVE-2024-57874", "CVE-2024-57876", "CVE-2024-57883", "CVE-2024-57884", "CVE-2024-57888", "CVE-2024-57890", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57924", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57946", "CVE-2024-57947", "CVE-2025-21638", "CVE-2025-21640", "CVE-2025-21648", "CVE-2025-21653", "CVE-2025-21662", "CVE-2025-21665", "CVE-2025-21683", "CVE-2025-21693", "CVE-2025-21694", "CVE-2025-21699");
  script_tag(name:"creation_date", value:"2025-04-11 04:27:44 +0000 (Fri, 11 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-03 14:53:23 +0000 (Mon, 03 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1360");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1360");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net: fix data-races around sk->sk_forward_alloc(CVE-2024-53124)

nvme-multipath: defer partition scanning(CVE-2024-53093)

bpf: sync_linked_regs() must preserve subreg_def(CVE-2024-53125)

KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN(CVE-2024-53135)

netlink: terminate outstanding dump on socket close(CVE-2024-53140)

media: ts2020: fix null-ptr-deref in ts2020_probe().(CVE-2024-56574)

drm/amd/display: Fix out-of-bounds access in 'dcn21_link_encoder_create'(CVE-2024-56608)

ftrace: Fix regression with module command in stack_trace_filter(CVE-2024-56569)

scsi: qedf: Fix a possible memory leak in qedf_alloc_and_init_sb().(CVE-2024-56748)

ovl: Filter invalid inodes with missing lookup function(CVE-2024-56570)

smb: client: fix NULL ptr deref in crypto_aead_setkey().(CVE-2024-53185)

vfio/pci: Properly hide first-in-list PCIe extended capability(CVE-2024-53214)

bpf: fix OOB devmap writes when deleting elemen(CVE-2024-56615)

io_uring: check if iowq is killed before queuing(CVE-2024-56709)

leds: class: Protect brightness_show() with led_cdev->led_access mutex(CVE-2024-56587)

io_uring: check for overflows in io_pin_pages(CVE-2024-53187)

RDMA/mlx5: Move events notifier registration to be after device registration(CVE-2024-53224)

scsi: sg: Fix slab-use-after-free read in sg_release()(CVE-2024-56631)

bpf, sockmap: Fix race between element replace and close()(CVE-2024-56664)

net: inet: do not leave a dangling sk pointer in inet_create().(CVE-2024-56601)

tipc: Fix use-after-free of kernel socket in cleanup_bearer().(CVE-2024-56642)

sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport(CVE-2024-56688)

ipv6: Fix soft lockups in fib6_select_path under high next hop churn(CVE-2024-56703)

rtc: check if __rtc_read_time was successful in rtc_timer_do_work()(CVE-2024-56739)

mm/mempolicy: fix migrate_to_node() assuming there is at least one VMA in a MM(CVE-2024-56611)

virtiofs: use pages instead of pointer for kernel direct IO(CVE-2024-53219)

PCI: Fix use-after-free of slot->bus on hot remove(CVE-2024-53194)

io_uring/tctx: work around xa_store() allocation error issue(CVE-2024-56584)

SUNRPC: make sure cache entry active before cache_show(CVE-2024-53174)

tcp_bpf: Fix the sk_mem_uncharge logic in tcp_bpf_sendmsg(CVE-2024-56633)

firmware: arm_scpi: Check the DVFS OPP count returned by the firmware(CVE-2024-53157)

crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY(CVE-2024-56690)

smb: client: fix use-after-free of signing key(CVE-2024-53179)

quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

netfilter: x_tables: fix LED ID check in led_tg_check().(CVE-2024-56650)

tracing: Prevent bad count for tracing_cpumask_write(CVE-2024-56763)

media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg(CVE-2024-56769)

nvme-pci: fix freeing of the HMB descriptor ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1841.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1841.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1841.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1841.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1841.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1841.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
