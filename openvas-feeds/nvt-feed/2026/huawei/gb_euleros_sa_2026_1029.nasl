# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1029");
  script_cve_id("CVE-2022-49084", "CVE-2022-50251", "CVE-2022-50252", "CVE-2022-50280", "CVE-2022-50299", "CVE-2022-50312", "CVE-2022-50315", "CVE-2022-50341", "CVE-2022-50350", "CVE-2022-50365", "CVE-2022-50381", "CVE-2022-50389", "CVE-2022-50402", "CVE-2022-50405", "CVE-2022-50410", "CVE-2022-50430", "CVE-2022-50435", "CVE-2022-50470", "CVE-2022-50482", "CVE-2022-50489", "CVE-2022-50494", "CVE-2022-50497", "CVE-2022-50516", "CVE-2022-50544", "CVE-2022-50552", "CVE-2022-50555", "CVE-2022-50566", "CVE-2023-52989", "CVE-2023-53148", "CVE-2023-53149", "CVE-2023-53150", "CVE-2023-53165", "CVE-2023-53204", "CVE-2023-53215", "CVE-2023-53220", "CVE-2023-53241", "CVE-2023-53254", "CVE-2023-53259", "CVE-2023-53265", "CVE-2023-53280", "CVE-2023-53285", "CVE-2023-53295", "CVE-2023-53296", "CVE-2023-53299", "CVE-2023-53307", "CVE-2023-53317", "CVE-2023-53318", "CVE-2023-53322", "CVE-2023-53343", "CVE-2023-53354", "CVE-2023-53357", "CVE-2023-53368", "CVE-2023-53380", "CVE-2023-53395", "CVE-2023-53427", "CVE-2023-53432", "CVE-2023-53438", "CVE-2023-53446", "CVE-2023-53454", "CVE-2023-53456", "CVE-2023-53480", "CVE-2023-53481", "CVE-2023-53500", "CVE-2023-53506", "CVE-2023-53521", "CVE-2023-53559", "CVE-2023-53560", "CVE-2023-53604", "CVE-2023-53619", "CVE-2023-53623", "CVE-2023-53675", "CVE-2023-53676", "CVE-2023-53695", "CVE-2023-53705", "CVE-2023-53716", "CVE-2023-53719", "CVE-2023-53728", "CVE-2023-53733", "CVE-2024-45008", "CVE-2025-38181", "CVE-2025-38352", "CVE-2025-38702", "CVE-2025-38718", "CVE-2025-39689", "CVE-2025-39697", "CVE-2025-39817", "CVE-2025-39841", "CVE-2025-39866", "CVE-2025-39883", "CVE-2025-39902", "CVE-2025-39964", "CVE-2025-39973", "CVE-2025-39998", "CVE-2025-40018", "CVE-2025-40044", "CVE-2025-40048");
  script_tag(name:"creation_date", value:"2026-01-14 14:12:08 +0000 (Wed, 14 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-23 02:33:32 +0000 (Fri, 23 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2026-1029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1029");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1029");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2026-1029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"scsi: ses: Fix slab-out-of-bounds in ses_intf_remove()(CVE-2023-53521)

binfmt_misc: fix shift-out-of-bounds in check_special_flags(CVE-2022-50497)

scsi: lpfc: Fix buffer free/clear order in deferred receive path(CVE-2025-39841)

mm/memory-failure: fix VM_BUG_ON_PAGE(PagePoisoned(page)) when unpoison memory(CVE-2025-39883)

md: Replace snprintf with scnprintf(CVE-2022-50299)

drivers: serial: jsm: fix some leaks in probe(CVE-2022-50312)

udf: Do not bother merging very long extents(CVE-2023-53506)

fbdev: fix potential buffer overflow in do_register_framebuffer()(CVE-2025-38702)

mm/slub: avoid accessing metadata when pointer is invalid in object_err()(CVE-2025-39902)

xhci: Remove device endpoints from bandwidth list when freeing the device(CVE-2022-50470)

HID: multitouch: Correct devm device reference for hidinput input_dev name(CVE-2023-53454)

ubi: ubi_wl_put_peb: Fix infinite loop when wear-leveling work failed(CVE-2023-53481)

thermal: intel_powerclamp: Use get_cpu() instead of smp_processor_id() to avoid crash(CVE-2022-50494)

md: fix a crash in mempool_free(CVE-2022-50381)

scsi: ses: Fix possible desc_ptr out-of-bounds accesses(CVE-2023-53675)

scsi: target: target_core_configfs: Add length check to avoid buffer overflow(CVE-2025-39998)

fs: dlm: fix invalid derefence of sb_lvbptr(CVE-2022-50516)

NFS: Fix a race when updating an existing write(CVE-2025-39697)

mmc: vub300: fix return value check of mmc_add_host()(CVE-2022-50251)

tpm: tpm_crb: Add the missed acpi_put_table() to fix memory leak(CVE-2022-50389)

scsi: qla4xxx: Add length check when parsing nlattrs(CVE-2023-53456)

ext4: avoid deadlock in fs reclaim with page writeback(CVE-2023-53149)

kobject: Add sanity check for kset->kobj.ktype in kset_register()(CVE-2023-53480)

scsi: target: iscsi: Fix buffer overflow in lio_target_nacl_info_show()(CVE-2023-53676)

udf: Fix uninitialized array access for some pathnames(CVE-2023-53165)

ext4: avoid crash when inline data creation follows DIO write(CVE-2022-50435)

cifs: Fix warning and UAF when destroy the MR list(CVE-2023-53427)

scsi: qla2xxx: Pointer may be dereferenced(CVE-2023-53150)

fs: writeback: fix use-after-free in __mark_inode_dirty()(CVE-2025-39866)

blk-mq: use quiesced elevator switch when reinitializing queues(CVE-2022-50552)

mm/swap: fix swap_info_struct race between swapoff and get_swap_pages()(CVE-2023-53623)

ata: ahci: Match EM_MAX_SLOTS with SATA_PMP_MAX_PORTS(CVE-2022-50315)

pnode: terminate at peers of source(CVE-2022-50280)

tracing: Fix race issue between cpu buffer write and swap(CVE-2023-53368)

igb: Fix igb_down hung on surprise removal(CVE-2023-53148)

udf: Do not update file length for failed writes to inline files(CVE-2023-53295)

usb: host: xhci: Fix potential memory leak in xhci_alloc_stream_info()(CVE-2022-50544)

cacheinfo: Fix shared_cpu_map to handle shared caches at different levels(CVE-2023-53254)

net/tunnel: wait ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1948.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1948.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1948.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1948.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1948.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
