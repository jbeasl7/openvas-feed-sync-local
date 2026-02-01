# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1091");
  script_cve_id("CVE-2022-21546", "CVE-2022-49124", "CVE-2022-49157", "CVE-2022-49158", "CVE-2022-49159", "CVE-2022-50255", "CVE-2022-50267", "CVE-2022-50306", "CVE-2022-50350", "CVE-2022-50390", "CVE-2022-50493", "CVE-2022-50554", "CVE-2023-53178", "CVE-2023-53250", "CVE-2023-53254", "CVE-2023-53401", "CVE-2023-53432", "CVE-2023-53491", "CVE-2023-53530", "CVE-2023-53661", "CVE-2023-53696", "CVE-2024-21823", "CVE-2024-36357", "CVE-2024-56616", "CVE-2024-58093", "CVE-2025-21772", "CVE-2025-21992", "CVE-2025-22022", "CVE-2025-22044", "CVE-2025-22083", "CVE-2025-37780", "CVE-2025-37885", "CVE-2025-38022", "CVE-2025-38174", "CVE-2025-38181", "CVE-2025-38200", "CVE-2025-38201", "CVE-2025-38207", "CVE-2025-38332", "CVE-2025-38387", "CVE-2025-38439", "CVE-2025-38474", "CVE-2025-38477", "CVE-2025-38502", "CVE-2025-38515", "CVE-2025-38540", "CVE-2025-38553", "CVE-2025-38556", "CVE-2025-38569", "CVE-2025-38584", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38622", "CVE-2025-38664", "CVE-2025-38678", "CVE-2025-38680", "CVE-2025-38683", "CVE-2025-38685", "CVE-2025-38691", "CVE-2025-38693", "CVE-2025-38701", "CVE-2025-38709", "CVE-2025-39681", "CVE-2025-39683", "CVE-2025-39689", "CVE-2025-39691", "CVE-2025-39724", "CVE-2025-39742", "CVE-2025-39744", "CVE-2025-39749", "CVE-2025-39752", "CVE-2025-39760", "CVE-2025-39782", "CVE-2025-39797", "CVE-2025-39798", "CVE-2025-39813", "CVE-2025-39817", "CVE-2025-39829", "CVE-2025-39847", "CVE-2025-39850", "CVE-2025-39851", "CVE-2025-39853", "CVE-2025-39865", "CVE-2025-39902", "CVE-2025-39945", "CVE-2025-39949", "CVE-2025-39953", "CVE-2025-39964", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39973", "CVE-2025-39993", "CVE-2025-40018", "CVE-2025-40019", "CVE-2025-40021", "CVE-2025-40026", "CVE-2025-40042", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40081", "CVE-2025-40083", "CVE-2025-40087", "CVE-2025-40105", "CVE-2025-40109", "CVE-2025-40167", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2026-01-14 14:12:08 +0000 (Wed, 14 Jan 2026)");
  script_version("2026-01-26T05:50:34+0000");
  script_tag(name:"last_modification", value:"2026-01-26 05:50:34 +0000 (Mon, 26 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-23 20:56:32 +0000 (Fri, 23 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2026-1091)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1091");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1091");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2026-1091 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net: drop UFO packets in udp_rcv_segment()(CVE-2025-38622)

A transient execution vulnerability in some AMD processors may allow an attacker to infer data in the L1D cache, potentially resulting in the leakage of sensitive information across privileged boundaries.(CVE-2024-36357)

x86/mce: Work around an erratum on fast string copy instructions(CVE-2022-49124)

scsi: qla2xxx: Implement ref count for SRB(CVE-2022-49159)

rcu: Fix rcu_read_unlock() deadloop due to IRQ work(CVE-2025-39744)

jbd2: prevent softlockup in jbd2_log_do_checkpoint()(CVE-2025-39782)

drm/ttm: fix undefined behavior in bit shift for TTM_TT_FLAG_PRIV_POPULATED(CVE-2022-50390)

crypto: essiv - Check ssize for decryption and in-place encryption(CVE-2025-40019)

media: dvb-frontends: w7090p: fix null-ptr-deref in w7090p_tuner_write_serpar and w7090p_tuner_read_serpar(CVE-2025-38693)

rcu: Protect ->defer_qs_iw_pending from data race(CVE-2025-39749)

fbdev: Fix vmalloc out-of-bounds write in fast_imageblit(CVE-2025-38685)

media: rc: fix races with imon_disconnect()(CVE-2025-39993)

mm: kmem: fix a NULL pointer dereference in obj_stock_flush_required()(CVE-2023-53401)

scsi: lpfc: Use memcpy() for BIOS version(CVE-2025-38332)

usb: core: config: Prevent OOB read in SS endpoint companion parsing(CVE-2025-39760)

scsi: qla2xxx: Fix premature hw access after PCI error(CVE-2022-49157)

fbcon: fix integer overflow in fbcon_do_set_font(CVE-2025-39967)

scsi: target: iscsi: Fix a race condition between login_work and the login thread(CVE-2022-50350)

mm: fix uprobe pte be overwritten when expanding vma(CVE-2025-38207)

scsi: qla2xxx: Fix crash when I/O abort times out(CVE-2022-50493)

media: uvcvideo: Fix 1-byte out-of-bounds read in uvc_parse_format()(CVE-2025-38680)

scsi: qla2xxx: Use raw_smp_processor_id() instead of smp_processor_id()(CVE-2023-53530)

fs/buffer: fix use-after-free when call bh_read() helper(CVE-2025-39691)

HID: quirks: Add quirk for 2 Chicony Electronics HP 5MP Cameras(CVE-2025-38540)

mmc: rtsx_pci: fix return value check of mmc_add_host()(CVE-2022-50267)

RDMA/mlx5: Initialize obj_event->obj_sub_list before xa_insert(CVE-2025-38387)

i40e: fix validation of VF state in get resources(CVE-2025-39969)

vxlan: Fix NPD when refreshing an FDB entry with a nexthop object(CVE-2025-39851)

tracing: Limit access to parser->buffer when trace_get_user failed(CVE-2025-39683)

firmware: dmi-sysfs: Fix null-ptr-deref in dmi_sysfs_register_handle(CVE-2023-53250)

perf: arm_spe: Prevent overflow in PERF_IDX2OFF()(CVE-2025-40081)

ARM: rockchip: fix kernel hang during smp initialization(CVE-2025-39752)

x86/cpu/hygon: Add missing resctrl_cpu_detect() in bsp_init helper(CVE-2025-39681)

i40e: Fix potential invalid access when MAC list is empty(CVE-2025-39853)

drm/dp_mst: Fix MST sideband message body length check(CVE-2024-56616)

vhost-scsi: Fix handling of multiple calls to ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2801.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2801.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2801.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2801.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2801.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2801.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
