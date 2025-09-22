# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01982.1");
  script_cve_id("CVE-2020-36790", "CVE-2020-36791", "CVE-2021-32399", "CVE-2022-3564", "CVE-2022-49110", "CVE-2022-49139", "CVE-2022-49320", "CVE-2022-49767", "CVE-2022-49769", "CVE-2022-49770", "CVE-2022-49771", "CVE-2022-49772", "CVE-2022-49775", "CVE-2022-49777", "CVE-2022-49787", "CVE-2022-49788", "CVE-2022-49789", "CVE-2022-49790", "CVE-2022-49793", "CVE-2022-49794", "CVE-2022-49799", "CVE-2022-49802", "CVE-2022-49809", "CVE-2022-49818", "CVE-2022-49821", "CVE-2022-49823", "CVE-2022-49824", "CVE-2022-49825", "CVE-2022-49826", "CVE-2022-49827", "CVE-2022-49830", "CVE-2022-49832", "CVE-2022-49835", "CVE-2022-49836", "CVE-2022-49839", "CVE-2022-49841", "CVE-2022-49842", "CVE-2022-49846", "CVE-2022-49861", "CVE-2022-49870", "CVE-2022-49879", "CVE-2022-49880", "CVE-2022-49881", "CVE-2022-49887", "CVE-2022-49889", "CVE-2022-49892", "CVE-2022-49906", "CVE-2022-49910", "CVE-2022-49915", "CVE-2022-49922", "CVE-2022-49927", "CVE-2023-1990", "CVE-2023-53039", "CVE-2023-53052", "CVE-2023-53106", "CVE-2024-53168", "CVE-2024-56558", "CVE-2024-56705", "CVE-2025-21812", "CVE-2025-21999", "CVE-2025-22028", "CVE-2025-22121", "CVE-2025-37789", "CVE-2025-37846", "CVE-2025-40364");
  script_tag(name:"creation_date", value:"2025-06-19 04:15:13 +0000 (Thu, 19 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-03 15:25:51 +0000 (Mon, 03 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01982-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501982-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243919");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040324.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:01982-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-32399: Fixed a race condition when removing the HCI controller (bsc#1184611).
- CVE-2022-49110: netfilter: conntrack: revisit gc autotuning (bsc#1237981).
- CVE-2022-49139: Bluetooth: fix null ptr deref on hci_sync_conn_complete_evt (bsc#1238032).
- CVE-2022-49320: dmaengine: zynqmp_dma: In struct zynqmp_dma_chan fix desc_size data type (bsc#1238394).
- CVE-2022-49767: 9p/trans_fd: always use O_NONBLOCK read/write (bsc#1242493).
- CVE-2022-49769: gfs2: Check sb_bsize_shift after reading superblock (bsc#1242440).
- CVE-2022-49770: ceph: avoid putting the realm twice when decoding snaps fails (bsc#1242597).
- CVE-2022-49775: tcp: cdg: allow tcp_cdg_release() to be called multiple times (bsc#1242245).
- CVE-2022-49789: scsi: zfcp: Fix double free of FSF request when qdio send fails (bsc#1242366).
- CVE-2023-53039: HID: intel-ish-hid: ipc: Fix potential use-after-free in work function (bsc#1242745).
- CVE-2024-53168: net: make sock_inuse_add() available (bsc#1234887).
- CVE-2024-56558: nfsd: make sure exp active before svc_export_show (bsc#1235100).
- CVE-2024-56705: media: atomisp: add check for rgby_data memory allocation failure (bsc#1235568).
- CVE-2025-21812: ax25: rcu protect dev->ax25_ptr (bsc#1238471).
- CVE-2025-21999: proc: fix UAF in proc_get_inode() (bsc#1240802).
- CVE-2025-22028: media: vimc: skip .s_stream() for stopped entities (bsc#1241362).
- CVE-2025-22121: ext4: fix out-of-bound read in ext4_xattr_inode_dec_ref_all() (bsc#1241593).
- CVE-2025-37789: net: openvswitch: fix nested key length validation in the set() action (bsc#1242762).
- CVE-2025-37846: arm64: mops: Do not dereference src reg for a set operation (bsc#1242963).
- CVE-2025-40364: io_uring: fix io_req_prep_async with provided buffers (bsc#1241637).

The following non-security bugs were fixed:

- blk: Drop a couple of block layer git-fixes (bsc#1170891 bsc#1173139).
- x86/entry: Remove skip_r11rcx (bsc#1201644, bsc#1201664, bsc#1201672, bsc#1201673, bsc#1201676).
- HID: intel-ish-hid: ipc: Fix dev_err usage with uninitialized dev->devc (bsc#1242745)
- kernel: Remove debug flavor (bsc#1243919).
- devm-helpers: Add resource managed version of work init (bsc#1242745).
- rpm: fixup 'rpm: support gz and zst compression methods' once more (bsc#1190428, bsc#1190358).
- mtd: phram: Add the kernel lock down check (bsc#1232649).
- ocfs2: fix the issue with discontiguous allocation in the global_bitmap (git-fixes).
- usb: roles: Call try_module_get() from usb_role_switch_find_by_fwnode() (git-fixes).
- usb: typec: tps6598x: Fix return value check in tps6598x_probe() (git-fixes).
- workqueue: Add resource managed version of delayed work init (bsc#1242745)");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.207.1.150300.18.124.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.207.1", rls:"SLES15.0SP3"))) {
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
