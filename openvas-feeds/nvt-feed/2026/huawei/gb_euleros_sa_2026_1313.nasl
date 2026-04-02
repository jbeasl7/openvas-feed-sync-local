# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1313");
  script_cve_id("CVE-2022-21546", "CVE-2022-49938", "CVE-2022-50033", "CVE-2022-50084", "CVE-2022-50253", "CVE-2022-50278", "CVE-2022-50347", "CVE-2022-50449", "CVE-2022-50505", "CVE-2022-50521", "CVE-2022-50531", "CVE-2022-50640", "CVE-2022-50646", "CVE-2022-50655", "CVE-2022-50664", "CVE-2022-50671", "CVE-2022-50749", "CVE-2022-50755", "CVE-2022-50774", "CVE-2022-50868", "CVE-2022-50884", "CVE-2023-53151", "CVE-2023-53245", "CVE-2023-53271", "CVE-2023-53313", "CVE-2023-53372", "CVE-2023-53431", "CVE-2023-53519", "CVE-2023-53548", "CVE-2023-53786", "CVE-2023-53799", "CVE-2023-53800", "CVE-2023-53803", "CVE-2023-53817", "CVE-2023-53821", "CVE-2023-53831", "CVE-2023-53832", "CVE-2023-53847", "CVE-2023-53853", "CVE-2023-53863", "CVE-2023-53998", "CVE-2023-54014", "CVE-2023-54015", "CVE-2023-54091", "CVE-2023-7324", "CVE-2024-56662", "CVE-2025-38095", "CVE-2025-38572", "CVE-2025-38709", "CVE-2025-39676", "CVE-2025-40115", "CVE-2025-40178", "CVE-2025-40196", "CVE-2025-40271", "CVE-2025-40322", "CVE-2025-40324", "CVE-2025-68241", "CVE-2025-68285", "CVE-2025-68349", "CVE-2025-68367");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-09 13:53:12 +0000 (Fri, 09 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2026-1313)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1313");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1313");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2026-1313 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"scsi: mpt3sas: Fix crash in transport port remove by using ioc_info()(CVE-2025-40115)

scsi: target: Fix WRITE_SAME No Data Buffer crash(CVE-2022-21546)

NFSD: Fix crash in nfsd4_read_release()(CVE-2025-40324)

scsi: qla4xxx: Prevent a potential error pointer dereference(CVE-2025-39676)

loop: Avoid updating block size under exclusive owner(CVE-2025-38709)

 media: v4l2-mem2mem: add lock to protect parameter num_rdy(CVE-2023-53519)

mmc: rtsx_usb_sdmmc: fix return value check of mmc_add_host()(CVE-2022-50347)

net: usbnet: Fix WARNING in usbnet_start_xmit/usb_submit_urb(CVE-2023-53548)

platform/x86: mxm-wmi: fix memleak in mxm_wmi_call_mx[ds<pipe>mx]()(CVE-2022-50521)

tipc: fix an information leak in tipc_topsrv_kern_subscr(CVE-2022-50531)

scsi: qla2xxx: Check valid rport returned by fc_bsg_to_rport()(CVE-2023-54014)

ubi: Fix unreferenced object reported by kmemleak in ubi_resize_volume()(CVE-2023-53271)

dma-buf: insert memory barrier before updating num_fences(CVE-2025-38095)

md/raid10: fix wrong setting of max_corr_read_errors(CVE-2023-53313)

scsi: ses: Fix possible addl_desc_ptr out-of-bounds accesses(CVE-2023-7324)

scsi: storvsc: Fix handling of virtual Fibre Channel timeouts(CVE-2023-53245)

md/raid10: prevent soft lockup while flush writes(CVE-2023-53151)

clk: samsung: Fix memory leak in _samsung_clk_register_pll()(CVE-2022-50449)

sctp: fix a potential overflow in sctp_ifwdtsn_skip(CVE-2023-53372)

crypto: api - Use work queue in crypto_destroy_instance(CVE-2023-53799)

drm: Prevent drm_copy_field() to attempt copying a NULL pointer(CVE-2022-50884)

dm raid: fix address sanitizer warning in raid_status(CVE-2022-50084)

cifs: fix small mempool leak in SMB2_negotiate()(CVE-2022-49938)

net/mlx5: Devcom, fix error flow in mlx5_devcom_register_device(CVE-2023-54015)

ipv6: reject malicious packets in ipv6_gso_segment()(CVE-2025-38572)

fs/proc: fix uaf in proc_readdir_de()(CVE-2025-40271)

scsi: ses: Fix slab-out-of-bounds in ses_enclosure_data_process()(CVE-2023-53803)

macintosh/mac_hid: fix race condition in mac_hid_toggle_emumouse(CVE-2025-68367)

ubi: Fix use-after-free when volume resizing failed(CVE-2023-53800)

crypto: qat - fix DMA transfer direction(CVE-2022-50774)

scsi: hpsa: Fix possible memory leak in hpsa_init_one()(CVE-2022-50646)

mmc: core: Fix kernel panic when remove non-standard SDIO card(CVE-2022-50640)

usb: host: ohci-ppc-of: Fix refcount leak bug(CVE-2022-50033)

PNP: fix name memory leak in pnp_alloc_dev()(CVE-2022-50278)

media: dvb-frontends: fix leak of memory fw(CVE-2022-50664)

fs: quota: create dedicated workqueue for quota_release_work(CVE-2025-40196)

acpi: nfit: vmalloc-out-of-bounds Read in acpi_nfit_ctl(CVE-2024-56662)

scsi: ses: Handle enclosure with just a primary component gracefully(CVE-2023-53431)

pid: Add a judgment for ns null in pid_nr_ns(CVE-2025-40178)

NFSv4/pNFS: Clear NFS_INO_LAYOUTCOMMIT in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1972.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1972.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1972.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1972.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1972.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
