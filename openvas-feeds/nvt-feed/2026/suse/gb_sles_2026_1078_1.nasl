# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1078.1");
  script_cve_id("CVE-2022-50453", "CVE-2023-53794", "CVE-2023-53802", "CVE-2023-53808", "CVE-2023-53816", "CVE-2023-53817", "CVE-2023-53827", "CVE-2023-54184", "CVE-2023-6040", "CVE-2025-21738", "CVE-2025-22083", "CVE-2025-22125", "CVE-2025-39748", "CVE-2025-39817", "CVE-2025-39964", "CVE-2025-39998", "CVE-2025-40099", "CVE-2025-40103", "CVE-2025-40219", "CVE-2025-40220", "CVE-2025-40242", "CVE-2025-40342", "CVE-2025-68223", "CVE-2025-68234", "CVE-2025-68283", "CVE-2025-68285", "CVE-2025-68287", "CVE-2025-68295", "CVE-2025-68724", "CVE-2025-68818", "CVE-2025-71075", "CVE-2025-71104", "CVE-2025-71113", "CVE-2025-71116", "CVE-2025-71131", "CVE-2025-71183", "CVE-2025-71184", "CVE-2025-71194", "CVE-2025-71224", "CVE-2025-71236", "CVE-2026-22991", "CVE-2026-22998", "CVE-2026-23003", "CVE-2026-23004", "CVE-2026-23054", "CVE-2026-23060", "CVE-2026-23064", "CVE-2026-23069", "CVE-2026-23074", "CVE-2026-23083", "CVE-2026-23084", "CVE-2026-23085", "CVE-2026-23086", "CVE-2026-23089", "CVE-2026-23095", "CVE-2026-23099", "CVE-2026-23105", "CVE-2026-23112", "CVE-2026-23125", "CVE-2026-23141", "CVE-2026-23191", "CVE-2026-23198", "CVE-2026-23204", "CVE-2026-23208", "CVE-2026-23209", "CVE-2026-23268", "CVE-2026-23269", "CVE-2026-25702");
  script_tag(name:"creation_date", value:"2026-03-30 04:58:33 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-09 18:31:36 +0000 (Mon, 09 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1078-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1078-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261078-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259857");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024954.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:1078-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-50453: gpiolib: cdev: fix NULL-pointer dereferences (bsc#1250887).
- CVE-2023-53794: cifs: fix session state check in reconnect to avoid use-after-free issue (bsc#1255163).
- CVE-2023-53802: wifi: ath9k: htc_hst: free skb in ath9k_htc_rx_msg() if there is no callback function (bsc#1254725).
- CVE-2023-53808: wifi: mwifiex: fix memory leak in mwifiex_histogram_read() (bsc#1254723).
- CVE-2023-53816: drm/amdkfd: fix potential kgd_mem UAFs (bsc#1254958).
- CVE-2023-53817: crypto: lib/mpi - avoid null pointer deref in mpi_cmp_ui() (bsc#1254992).
- CVE-2023-53827: Bluetooth: L2CAP: Fix use-after-free in l2cap_disconnect_{req,rsp} (bsc#1255049).
- CVE-2023-54184: scsi: target: iscsit: Free cmds before session free (bsc#1255991).
- CVE-2025-21738: ata: libata-sff: Ensure that we cannot write outside the allocated buffer (bsc#1238917).
- CVE-2025-22083: vhost-scsi: Fix handling of multiple calls to vhost_scsi_set_endpoint (bsc#1241414).
- CVE-2025-22125: md/raid1,raid10: do not ignore IO flags (bsc#1241596).
- CVE-2025-39748: bpf: Forget ranges when refining tnum after JSET (bsc#1249587).
- CVE-2025-39817: efivarfs: Fix slab-out-of-bounds in efivarfs_d_compare (bsc#1249998).
- CVE-2025-39964: crypto: af_alg - Disallow concurrent writes in af_alg_sendmsg (bsc#1251966).
- CVE-2025-39998: scsi: target: target_core_configfs: Add length check to avoid buffer overflow (bsc#1252073).
- CVE-2025-40099: cifs: parse_dfs_referrals: prevent oob on malformed input (bsc#1252911).
- CVE-2025-40103: smb: client: Fix refcount leak for cifs_sb_tlink (bsc#1252924).
- CVE-2025-40219: PCI/IOV: Add PCI rescan-remove locking when enabling/disabling SR-IOV (bsc#1254518).
- CVE-2025-40220: fuse: fix livelock in synchronous file put from fuseblk workers (bsc#1254520).
- CVE-2025-40242: gfs2: Fix unlikely race in gdlm_put_lock (bsc#1255075).
- CVE-2025-40342: nvme-fc: use lock accessing port_state and rport state (bsc#1255274).
- CVE-2025-68223: drm/radeon: delete radeon_fence_process in is_signaled, no deadlock (bsc#1255357).
- CVE-2025-68234: scsi: imm: Fix use-after-free bug caused by unfinished delayed work (bsc#1255416).
- CVE-2025-68283: libceph: replace BUG_ON with bounds check for map->max_osd (bsc#1255379).
- CVE-2025-68285: libceph: fix potential use-after-free in have_mon_and_osd_map() (bsc#1255401).
- CVE-2025-68287: usb: dwc3: Fix race condition between concurrent dwc3_remove_requests() call paths (bsc#1255152).
- CVE-2025-68295: smb: client: fix memory leak in cifs_construct_tcon() (bsc#1255129).
- CVE-2025-68724: crypto: asymmetric_keys - prevent overflow in asymmetric_key_generate_id (bsc#1255550).
- CVE-2025-68818: scsi: qla2xxx: Perform lockless command completion in abort path (bsc#1256675).
- CVE-2025-71075: scsi: aic94xx: fix use-after-free in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.296.1", rls:"SLES12.0SP5"))) {
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
