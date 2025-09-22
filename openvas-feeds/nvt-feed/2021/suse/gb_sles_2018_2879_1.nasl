# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2879.1");
  script_cve_id("CVE-2018-10902", "CVE-2018-10940", "CVE-2018-12896", "CVE-2018-14617", "CVE-2018-14634", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 13:53:37 +0000 (Thu, 25 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2879-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2879-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182879-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108912");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004605.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2879-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-14617: Prevent NULL pointer dereference and panic in
 hfsplus_lookup() when opening a file (that is purportedly a hard link) in an
 hfs+ filesystem that has malformed catalog data, and is mounted read-only
 without a metadata directory (bsc#1102870).
- CVE-2018-16276: Incorrect bounds checking in the yurex USB driver in
 yurex_read allowed local attackers to use user access read/writes to crash the
 kernel or potentially escalate privileges (bsc#1106095).
- CVE-2018-15594: Ensure correct handling of indirect calls, to prevent
 attackers for conducting Spectre-v2 attacks against paravirtual guests
 (bsc#1105348).
- CVE-2018-14634: Prevent integer overflow in create_elf_tables that allowed a
 local attacker to exploit this vulnerability via a SUID-root binary and obtain
 full root privileges (bsc#1108912)
- CVE-2018-12896: Prevent integer overflow in the POSIX timer code that was
 caused by the way the overrun accounting works. Depending on interval and
 expiry time values, the overrun can be larger than INT_MAX, but the accounting
 is int based. This basically made the accounting values, which are visible to
 user space via timer_getoverrun(2) and siginfo::si_overrun, random. This
 allowed a local user to cause a denial of service (signed integer overflow) via
 crafted mmap, futex, timer_create, and timer_settime system calls (bnc#1099922)
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
- CVE-2018-15572: The spectre_v2_select_mitigation function did not always fill
 RSB upon a context switch, which made it easier for attackers to conduct
 userspace-userspace spectreRSB attacks (bnc#1102517)
- CVE-2018-10902: Protect against concurrent access to prevent double realloc
 (double free) in snd_rawmidi_input_params() and snd_rawmidi_output_status(). A
 malicious local attacker could have used this for privilege escalation
 (bnc#1105322)
- CVE-2018-14734: ucma_leave_multicast accessed a certain data structure after
 a cleanup step in ucma_process_join, which allowed attackers to cause a denial
 of service (use-after-free) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.71.1", rls:"SLES11.0SP4"))) {
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
