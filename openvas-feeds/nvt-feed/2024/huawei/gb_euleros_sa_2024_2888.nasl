# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2888");
  script_cve_id("CVE-2021-47400", "CVE-2021-47423", "CVE-2021-47434", "CVE-2022-48732", "CVE-2022-48788", "CVE-2022-48828", "CVE-2022-48879", "CVE-2022-48899", "CVE-2022-48937", "CVE-2022-48943", "CVE-2023-52880", "CVE-2023-52898", "CVE-2024-26852", "CVE-2024-26921", "CVE-2024-40959", "CVE-2024-40978", "CVE-2024-41012", "CVE-2024-41014", "CVE-2024-41020", "CVE-2024-41035", "CVE-2024-41087", "CVE-2024-41095", "CVE-2024-42070", "CVE-2024-42084", "CVE-2024-42102", "CVE-2024-42131", "CVE-2024-42145", "CVE-2024-42154", "CVE-2024-42244", "CVE-2024-42265", "CVE-2024-42285", "CVE-2024-42286", "CVE-2024-42289", "CVE-2024-42292", "CVE-2024-42304", "CVE-2024-42305", "CVE-2024-42312", "CVE-2024-43830", "CVE-2024-43853", "CVE-2024-43856", "CVE-2024-43861", "CVE-2024-43871", "CVE-2024-43882", "CVE-2024-43890", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43914", "CVE-2024-44944", "CVE-2024-44987", "CVE-2024-45006", "CVE-2024-46800");
  script_tag(name:"creation_date", value:"2024-11-11 04:32:03 +0000 (Mon, 11 Nov 2024)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 17:18:55 +0000 (Fri, 20 Sep 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2888)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2888");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2888");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2888 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"scsi: qedi: Fix crash while reading debugfs attribute(CVE-2024-40978)

drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes(CVE-2024-41095)

drm/ nouveau/debugfs: fix file release memory leak(CVE-2021-47423)

USB: serial: mos7840: fix crash on resume(CVE-2024-42244)

NFSD: Fix ia_size underflow(CVE-2022-48828)

xhci: Fix command ring pointer corruption while aborting a command(CVE-2021-47434)

ata: libata-core: Fix double free on error(CVE-2024-41087)

xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

ftruncate: pass a signed offset(CVE-2024-42084)

ext4: check dot and dotdot of dx_root before making dir indexed(CVE-2024-42305)

ext4: make sure the first directory block is not a hole(CVE-2024-42304)

leds: trigger: Unregister sysfs attributes before calling deactivate()(CVE-2024-43830)

Revert 'mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again'(CVE-2024-42102)

filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

protect the fetch of ->fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

mm: avoid overflows in dirty throttling logic(CVE-2024-42131)

kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

memcg: protect concurrent access to mem_cgroup_idr(CVE-2024-43892)

dma: fix call order in dmam_free_coherent(CVE-2024-43856)

drm/ nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

drm/virtio: Fix GEM handle creation UAF(CVE-2022-48899)

cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

net: usb: qmi_wwan: fix memory leak for not ip packets(CVE-2024-43861)

md/raid5: avoid BUG_ON() while continue reshape after reassembling(CVE-2024-43914)

netfilter: ctnetlink: use helper function to calculate expect ID(CVE-2024-44944)

RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

KVM: x86/mmu: make apf token non-zero to fix bug(CVE-2022-48943)

efi: fix NULL-deref in init error path(CVE-2022-48879)

nvme-rdma: fix possible use-after-free in transport error_recovery work(CVE-2022-48788)

devres: Fix memory leakage caused by driver ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h1912.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h1912.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h1912.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h1912.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h1912.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
