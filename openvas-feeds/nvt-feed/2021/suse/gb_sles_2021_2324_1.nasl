# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2324.1");
  script_cve_id("CVE-2019-25045", "CVE-2020-24588", "CVE-2020-26558", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-33624", "CVE-2021-34693");
  script_tag(name:"creation_date", value:"2021-07-15 09:14:13 +0000 (Thu, 15 Jul 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 15:36:04 +0000 (Tue, 06 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2324-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2324-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212324-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188010");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009141.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2324-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-33624: Fixed a bug which allows unprivileged BPF program to leak the contents of arbitrary kernel memory (and therefore, of all physical memory) via a side-channel. (bsc#1187554)
- CVE-2019-25045: Fixed an use-after-free issue in the Linux kernel The XFRM subsystem, related to an xfrm_state_fini panic. (bsc#1187049)
- CVE-2021-0605: Fixed an out-of-bounds read which could lead to local information disclosure in the kernel with System execution privileges needed. (bsc#1187601)
- CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to local escalation of privilege with no additional execution privileges needed. (bsc#1187595)
- CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure pairing that could permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing. (bsc#1179610)
- CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local users to obtain sensitive information from kernel stack memory because parts of a data structure are uninitialized. (bsc#1187452)
- CVE-2021-0129: Fixed an improper access control in BlueZ that may have allowed an authenticated user to potentially enable information disclosure via adjacent access. (bsc#1186463)
- CVE-2020-36386: Fixed an out-of-bounds read in hci_extended_inquiry_result_evt. (bsc#1187038)
- CVE-2020-24588: Fixed a bug that could allow an adversary to abuse devices that support receiving non-SSP A-MSDU frames to inject arbitrary network packets. (bsc#1185861)

The following non-security bugs were fixed:

- ALSA: timer: Fix master timer notification (git-fixes).
- alx: Fix an error handling path in 'alx_probe()' (git-fixes).
- ASoC: sti-sas: add missing MODULE_DEVICE_TABLE (git-fixes).
- batman-adv: Avoid WARN_ON timing related checks (git-fixes).
- blk-mq: Swap two calls in blk_mq_exit_queue() (bsc#1187453).
- blk-wbt: Fix missed wakeup (bsc#1186627).
- block: Discard page cache of zone reset target range (bsc#1187402).
- Bluetooth: fix the erroneous flush_work() order (git-fixes).
- Bluetooth: use correct lock to prevent UAF of hdev object (git-fixes).
- btrfs: account for new extents being deleted in total_bytes_pinned (bsc#1135481).
- btrfs: add a comment explaining the data flush steps (bsc#1135481).
- btrfs: add btrfs_reserve_data_bytes and use it (bsc#1135481).
- btrfs: add flushing states for handling data reservations (bsc#1135481).
- btrfs: add missing error handling after doing leaf/node binary search (bsc#1187833).
- btrfs: add the data transaction commit logic into may_commit_transaction (bsc#1135481).
- btrfs: call btrfs_try_granting_tickets when freeing reserved bytes (bsc#1135481).
- btrfs: call btrfs_try_granting_tickets when reserving space (bsc#1135481).
- btrfs: call btrfs_try_granting_tickets when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.77.1", rls:"SLES12.0SP5"))) {
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
