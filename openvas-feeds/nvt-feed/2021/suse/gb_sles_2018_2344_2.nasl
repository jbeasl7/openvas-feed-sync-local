# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2344.2");
  script_cve_id("CVE-2017-18344", "CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391", "CVE-2018-5814", "CVE-2018-9385");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 21:37:19 +0000 (Wed, 12 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2344-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2344-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182344-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103580");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004737.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2344-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-3620: Local attackers on baremetal systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data. (bnc#1087081).
- CVE-2018-3646: Local attackers in virtualized guest systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data, even from other virtual machines or the host system. (bnc#1089343).
- CVE-2018-5390 aka 'SegmentSmack': The Linux Kernel can be forced to make very expensive calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for every incoming packet which can lead to a denial of service (bnc#1102340).
- CVE-2018-5391 aka 'FragmentSmack': A flaw in the IP packet reassembly could be used by remote attackers to consume lots of CPU time (bnc#1103097).
- CVE-2018-14734: drivers/infiniband/core/ucma.c allowed ucma_leave_multicast to access a certain data structure after a cleanup step in ucma_process_join, which allowed attackers to cause a denial of service (use-after-free) (bnc#1103119).
- CVE-2017-18344: The timer_create syscall implementation in kernel/time/posix-timers.c didn't properly validate the sigevent->sigev_notify field, which leads to out-of-bounds access in the show_timer function (called when /proc/$PID/timers is read). This allowed userspace applications to read arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE) (bnc#1102851 bnc#1103580).
- CVE-2018-9385: When printing the 'driver_override' option from with-in the amba driver, a very long line could expose one additional uninitialized byte (bnc#1100491).
- CVE-2018-13053: The alarm_timer_nsleep function in kernel/time/alarmtimer.c had an integer overflow via a large relative timeout because ktime_add_safe is not used (bnc#1099924).
- CVE-2018-13405: The inode_init_owner function in fs/inode.c allowed local users to create files with an unintended group ownership, in a scenario where a directory is SGID to a certain group and is writable by a user who is not a member of that group. Here, the non-member can trigger creation of a plain file whose group ownership is that group. The intended behavior was that the non-member can trigger creation of a directory (but not a plain file) whose group ownership is that group. The non-member can escalate privileges by making the plain file executable and SGID (bnc#1100416).
- CVE-2018-13406: An integer overflow in the uvesafb_setcmap function in drivers/video/fbdev/uvesafb.c could result in local attackers being able to crash the kernel or potentially elevate privileges because kmalloc_array ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.92.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_92-default", rpm:"kgraft-patch-4_4_121-92_92-default~1~3.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules", rpm:"lttng-modules~2.7.1~9.4.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default", rpm:"lttng-modules-kmp-default~2.7.1_k4.4.121_92.92~9.4.1", rls:"SLES12.0SP2"))) {
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
