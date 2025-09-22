# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2920.1");
  script_cve_id("CVE-2015-9004", "CVE-2016-10229", "CVE-2016-10277", "CVE-2016-9604", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11176", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12762", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-15649", "CVE-2017-2647", "CVE-2017-6346", "CVE-2017-6951", "CVE-2017-7482", "CVE-2017-7487", "CVE-2017-7518", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8106", "CVE-2017-8831", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-25 14:55:05 +0000 (Fri, 25 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2920-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2920-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172920-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990682");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003367.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2920-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 GA LTS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-15649: net/packet/af_packet.c in the Linux kernel allowed local users to gain privileges via crafted system calls that trigger mishandling of packet_fanout data structures, because of a race condition (involving fanout_add and packet_do_bind) that leads to a use-after-free, a different vulnerability than CVE-2017-6346 (bnc#1064388).
- CVE-2015-9004: kernel/events/core.c in the Linux kernel mishandled counter grouping, which allowed local users to gain privileges via a crafted application, related to the perf_pmu_register and perf_event_open functions (bnc#1037306).
- CVE-2016-10229: udp.c in the Linux kernel allowed remote attackers to execute arbitrary code via UDP traffic that triggers an unsafe second checksum calculation during execution of a recv system call with the MSG_PEEK flag (bnc#1032268).
- CVE-2016-9604: The handling of keyrings starting with '.' in KEYCTL_JOIN_SESSION_KEYRING, which could have allowed local users to manipulate privileged keyrings, was fixed (bsc#1035576)
- CVE-2017-1000363: Linux drivers/char/lp.c Out-of-Bounds Write. Due to a missing bounds check, and the fact that parport_ptr integer is static, a 'secure boot' kernel command line adversary (can happen due to bootloader vulns, e.g. Google Nexus 6's CVE-2016-10277, where due to a vulnerability the adversary has partial control over the command line) can overflow the parport_nr array in the following code, by appending many (>LP_NO) 'lp=none' arguments to the command line (bnc#1039456).
- CVE-2017-1000365: The Linux Kernel imposes a size restriction on the arguments and environmental strings passed through RLIMIT_STACK/RLIM_INFINITY (1/4 of the size), but did not take the argument and environment pointers into account, which allowed attackers to bypass this limitation. (bnc#1039354).
- CVE-2017-1000380: sound/core/timer.c in the Linux kernel is vulnerable to a data race in the ALSA /dev/snd/timer driver resulting in local users being able to read information belonging to other users, i.e., uninitialized memory contents may be disclosed when a read and an ioctl happen at the same time (bnc#1044125).
- CVE-2017-10661: Race condition in fs/timerfd.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing (bnc#1053152).
- CVE-2017-11176: The mq_notify function in the Linux kernel did not set the sock pointer to NULL upon entry into the retry logic. During a user-space close of a Netlink socket, it allowed attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact (bnc#1048275).
- CVE-2017-12153: A security flaw was discovered in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.61~52.101.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_101-default", rpm:"kgraft-patch-3_12_61-52_101-default~1~8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_101-xen", rpm:"kgraft-patch-3_12_61-52_101-xen~1~8.1", rls:"SLES12.0"))) {
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
