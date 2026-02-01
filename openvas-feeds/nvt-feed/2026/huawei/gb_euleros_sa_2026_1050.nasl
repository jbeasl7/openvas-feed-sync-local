# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1050");
  script_cve_id("CVE-2022-49084", "CVE-2022-50220", "CVE-2022-50280", "CVE-2022-50315", "CVE-2022-50330", "CVE-2022-50350", "CVE-2022-50389", "CVE-2022-50435", "CVE-2022-50470", "CVE-2022-50497", "CVE-2022-50544", "CVE-2022-50552", "CVE-2022-50566", "CVE-2023-53149", "CVE-2023-53150", "CVE-2023-53165", "CVE-2023-53176", "CVE-2023-53285", "CVE-2023-53307", "CVE-2023-53317", "CVE-2023-53318", "CVE-2023-53368", "CVE-2023-53395", "CVE-2023-53437", "CVE-2023-53446", "CVE-2023-53456", "CVE-2023-53480", "CVE-2023-53506", "CVE-2023-53515", "CVE-2023-53548", "CVE-2023-53560", "CVE-2023-53567", "CVE-2023-53604", "CVE-2023-53728", "CVE-2025-38181", "CVE-2025-38320", "CVE-2025-38352", "CVE-2025-38449", "CVE-2025-38474", "CVE-2025-38494", "CVE-2025-38498", "CVE-2025-38515", "CVE-2025-39683", "CVE-2025-39689", "CVE-2025-39865", "CVE-2025-39866", "CVE-2025-39964", "CVE-2025-40044");
  script_tag(name:"creation_date", value:"2026-01-14 14:12:08 +0000 (Wed, 14 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-23 02:33:32 +0000 (Fri, 23 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2026-1050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1050");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1050");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2026-1050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"media: uvcvideo: Handle cameras with invalid descriptors(CVE-2023-53437)

scsi: target: iscsi: Fix a race condition between login_work and the login thread(CVE-2022-50350)

crypto: cavium - prevent integer overflow loading firmware(CVE-2022-50330)

HID: core: do not bypass hid_hw_raw_request(CVE-2025-38494)

tpm: tpm_crb: Add the missed acpi_put_table() to fix memory leak(CVE-2022-50389)

scsi: qla4xxx: Add length check when parsing nlattrs(CVE-2023-53456)

virtio-mmio: don't break lifecycle of vm_dev(CVE-2023-53515)

scsi: qla2xxx: Pointer may be dereferenced(CVE-2023-53150)

tracing/histograms: Add histograms to hist_vars if they have referenced variables(CVE-2023-53560)

fs: writeback: fix use-after-free in __mark_inode_dirty()(CVE-2025-39866)

ata: ahci: Match EM_MAX_SLOTS with SATA_PMP_MAX_PORTS(CVE-2022-50315)

pnode: terminate at peers of source(CVE-2022-50280)

drm/sched: Increment job count before swapping tail spsc queue(CVE-2025-38515)

tracing: Fix race issue between cpu buffer write and swap(CVE-2023-53368)

usb: host: xhci: Fix potential memory leak in xhci_alloc_stream_info()(CVE-2022-50544)

mtd: Fix device name leak when register device failed in add_mtd_device()(CVE-2022-50566)

ext4: add bounds checking in get_max_inline_xattr_value_size()(CVE-2023-53285)

tee: fix NULL pointer dereference in tee_shm_put(CVE-2025-39865)

crypto: af_alg - Disallow concurrent writes in af_alg_sendmsg(CVE-2025-39964)

do_change_type(): refuse to operate on unmounted/not ours mounts(CVE-2025-38498)

drm/gem: Acquire references on GEM handles for framebuffers(CVE-2025-38449)

dm integrity: call kmem_cache_destroy() in dm_integrity_init() error path(CVE-2023-53604)

qede: confirm skb is allocated before using(CVE-2022-49084)

recordmcount: Fix memory leaks in the uwrite function(CVE-2023-53318)

ACPICA: Add AML_NO_OPERAND_RESOLVE flag to Timer(CVE-2023-53395)

usb: net: sierra: check for no status endpoint(CVE-2025-38474)

posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del()(CVE-2025-38352)

ext4: avoid deadlock in fs reclaim with page writeback(CVE-2023-53149)

kobject: Add sanity check for kset->kobj.ktype in kset_register()(CVE-2023-53480)

PCI/ASPM: Disable ASPM on MFD function removal to avoid use-after-free(CVE-2023-53446)

tracing: Limit access to parser->buffer when trace_get_user failed(CVE-2025-39683)

binfmt_misc: fix shift-out-of-bounds in check_special_flags(CVE-2022-50497)

arm64/ptrace: Fix stack-out-of-bounds read in regs_get_kernel_stack_nth()(CVE-2025-38320)

udf: Fix uninitialized array access for some pathnames(CVE-2023-53165)

ext4: avoid crash when inline data creation follows DIO write(CVE-2022-50435)

serial: 8250: Reinit port->pm on port specific driver unbind(CVE-2023-53176)

rbd: avoid use-after-free in do_rbd_add() when rbd_dev_create() fails(CVE-2023-53307)

udf: Do not bother merging very long ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h2100.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h2100.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h2100.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h2100.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h2100.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
