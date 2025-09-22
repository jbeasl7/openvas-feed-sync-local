# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2908.1");
  script_cve_id("CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-10902", "CVE-2018-10940", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-14617", "CVE-2018-14634", "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 13:53:37 +0000 (Thu, 25 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2908-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2908-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182908-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108912");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004618.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2908-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-14634: Prevent integer overflow in create_elf_tables that allowed a
 local attacker to exploit this vulnerability via a SUID-root binary and obtain
 full root privileges (bsc#1108912)
- CVE-2018-14617: Prevent NULL pointer dereference and panic in
 hfsplus_lookup() when opening a file (that is purportedly a hard link) in an
 hfs+ filesystem that has malformed catalog data, and is mounted read-only
 without a metadata directory (bsc#1102870)
- CVE-2018-16276: Incorrect bounds checking in the yurex USB driver in
 yurex_read allowed local attackers to use user access read/writes to crash the
 kernel or potentially escalate privileges (bsc#1106095)
- CVE-2018-12896: Prevent integer overflow in the POSIX timer code that was
 caused by the way the overrun accounting works. Depending on interval and
 expiry time values, the overrun can be larger than INT_MAX, but the accounting
 is int based. This basically made the accounting values, which are visible to
 user space via timer_getoverrun(2) and siginfo::si_overrun, random. This
 allowed a local user to cause a denial of service (signed integer overflow) via
 crafted mmap, futex, timer_create, and timer_settime system calls (bnc#1099922)
- CVE-2018-13093: Prevent NULL pointer dereference and panic in lookup_slow()
 on a NULL inode->i_ops pointer when doing pathwalks on a corrupted xfs image.
 This occurred because of a lack of proper validation that cached inodes are free
 during allocation (bnc#1100001)
- CVE-2018-10940: The cdrom_ioctl_media_changed function allowed local
 attackers to use a incorrect bounds check in the CDROM driver
 CDROM_MEDIA_CHANGED ioctl to read out kernel memory (bsc#1092903)
- CVE-2018-16658: Prevent information leak in cdrom_ioctl_drive_status that
 could have been used by local attackers to read kernel memory (bnc#1107689)
- CVE-2018-6555: The irda_setsockopt function allowed local users to cause a
 denial of service (ias_object use-after-free and system crash) or possibly have
 unspecified other impact via an AF_IRDA socket (bnc#1106511)
- CVE-2018-6554: Prevent memory leak in the irda_bind function that allowed
 local users to cause a denial of service (memory consumption) by repeatedly
 binding an AF_IRDA socket (bnc#1106509)
- CVE-2018-10902: Protect against concurrent access to prevent double realloc
 (double free) in snd_rawmidi_input_params() and snd_rawmidi_output_status(). A
 malicious local attacker could have used this for privilege escalation
 (bnc#1105322)
- CVE-2018-10879: A local user could have caused a use-after-free in
 ext4_xattr_set_entry function and a denial of service or unspecified other
 impact by renaming a file in a crafted ext4 filesystem image (bsc#1099844)
- CVE-2018-10883: A local user could have caused an out-of-bounds write in
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.104.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.104.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.104.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.104.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.104.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.104.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.104.1", rls:"SLES12.0SP1"))) {
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
