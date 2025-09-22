# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2389.1");
  script_cve_id("CVE-2014-9922", "CVE-2016-10277", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-11176", "CVE-2017-11473", "CVE-2017-2647", "CVE-2017-6951", "CVE-2017-7482", "CVE-2017-7487", "CVE-2017-7533", "CVE-2017-7542", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-31 17:33:40 +0000 (Wed, 31 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2389-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2389-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172389-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/784815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995542");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-September/003193.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2389-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-7482: Several missing length checks ticket decode allowing for information leak or potentially code execution (bsc#1046107).
- CVE-2016-10277: Potential privilege escalation due to a missing bounds check in the lp driver. A kernel command-line adversary can overflow the parport_nr array to execute code (bsc#1039456).
- CVE-2017-7542: The ip6_find_1stfragopt function in net/ipv6/output_core.c in the Linux kernel allowed local users to cause a denial of service (integer overflow and infinite loop) by leveraging the ability to open a raw socket (bsc#1049882).
- CVE-2017-7533: Bug in inotify code allowing privilege escalation (bsc#1049483).
- CVE-2017-11176: The mq_notify function in the Linux kernel did not set the sock pointer to NULL upon entry into the retry logic. During a user-space close of a Netlink socket, it allowed attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact (bsc#1048275).
- CVE-2017-11473: Buffer overflow in the mp_override_legacy_irq() function in arch/x86/kernel/acpi/boot.c in the Linux kernel allowed local users to gain privileges via a crafted ACPI table (bnc#1049603).
- CVE-2017-1000365: The Linux Kernel imposed a size restriction on the arguments and environmental strings passed through RLIMIT_STACK/RLIM_INFINITY (1/4 of the size), but did not take the argument and environment pointers into account, which allowed attackers to bypass this limitation. (bnc#1039354)
- CVE-2014-9922: The eCryptfs subsystem in the Linux kernel allowed local users to gain privileges via a large filesystem stack that includes an overlayfs layer, related to fs/ecryptfs/main.c and fs/overlayfs/super.c (bnc#1032340)
- CVE-2017-8924: The edge_bulk_in_callback function in drivers/usb/serial/io_ti.c in the Linux kernel allowed local users to obtain sensitive information (in the dmesg ringbuffer and syslog) from uninitialized kernel memory by using a crafted USB device (posing as an io_ti USB serial device) to trigger an integer underflow (bnc#1038982).
- CVE-2017-8925: The omninet_open function in drivers/usb/serial/omninet.c in the Linux kernel allowed local users to cause a denial of service (tty exhaustion) by leveraging reference count mishandling (bnc#1038981).
- CVE-2017-1000380: sound/core/timer.c was vulnerable to a data race in the ALSA /dev/snd/timer driver resulting in local users being able to read information belonging to other users, i.e., uninitialized memory contents could have bene disclosed when a read and an ioctl happen at the same time (bnc#1044125)
- CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c was too late in checking whether an overwrite of an skb data structure may occur, which allowed local users to cause a denial of service (system ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.7.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.7.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.7.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.7.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.7.1", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.7.1", rls:"SLES11.0SP4"))) {
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
