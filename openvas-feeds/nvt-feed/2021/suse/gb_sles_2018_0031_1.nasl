# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0031.1");
  script_cve_id("CVE-2017-11600", "CVE-2017-13167", "CVE-2017-15115", "CVE-2017-15868", "CVE-2017-16534", "CVE-2017-16538", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-8824");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 17:06:31 +0000 (Thu, 21 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0031-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180031-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072876");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003573.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 LTSS kernel was updated to receive various security and bugfixes.

This update adds mitigations for various side channel attacks against modern CPUs that could disclose content of otherwise unreadable memory
(bnc#1068032).

- CVE-2017-5753 / 'SpectreAttack': Local attackers on systems with modern
 CPUs featuring deep instruction pipelining could use attacker
 controllable speculative execution over code patterns in the Linux
 Kernel to leak content from otherwise not readable memory in the same
 address space, allowing retrieval of passwords, cryptographic keys
 and other secrets.

 This problem is mitigated by adding speculative fencing on affected
 code paths throughout the Linux kernel.

 This issue is addressed for the x86_64, IBM Power and IBM zSeries
 architecture.

- CVE-2017-5715 / 'SpectreAttack': Local attackers on systems with modern
 CPUs featuring branch prediction could use mispredicted branches to
 speculatively execute code patterns that in turn could be made to
 leak other non-readable content in the same address space, an attack
 similar to CVE-2017-5753.

 This problem is mitigated by disabling predictive branches, depending
 on CPU architecture either by firmware updates and/or fixes in the
 user-kernel privilege boundaries.

 This is done with help of Linux Kernel fixes on the Intel/AMD x86_64
 and IBM zSeries architectures. On x86_64, this requires also updates
 of the CPU microcode packages, delivered in seperate updates.

 For IBM Power and zSeries the required firmware updates are supplied
 over regular channels by IBM.

 As this feature can have a performance impact, it can be disabled
 using the 'nospec' kernel commandline option.

- CVE-2017-5754 / 'MeltdownAttack': Local attackers on systems with
 modern CPUs featuring deep instruction pipelining could use code
 patterns in userspace to speculative executive code that would read
 otherwise read protected memory, an attack similar to CVE-2017-5753.

 This problem is mitigated by unmapping the Linux Kernel from the user
 address space during user code execution, following a approach called
 'KAISER'. The terms used here are 'KAISER' / 'Kernel Address Isolation'
 and 'PTI' / 'Page Table Isolation'.

 This update does this on the x86_64 architecture, it is not required
 on the IBM zSeries architecture.

 This feature can be enabled / disabled by the 'pti=[on<pipe>off<pipe>auto]' or
 'nopti' commandline options.

The following security bugs were fixed:

- CVE-2017-15868: The bnep_add_connection function in net/bluetooth/bnep/core.c in the Linux kernel did not ensure that an l2cap socket is available, which allowed local users to gain privileges via a crafted application (bnc#1071470).
- CVE-2017-13167: An elevation of privilege vulnerability in the kernel sound timer. (bnc#1072876).
- CVE-2017-16538: drivers/media/usb/dvb-usb-v2/lmedm04.c in the Linux kernel ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.69.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.69.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.69.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.69.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.69.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.69.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.69.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_69-default", rpm:"kgraft-patch-3_12_74-60_64_69-default~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_69-xen", rpm:"kgraft-patch-3_12_74-60_64_69-xen~1~2.3.1", rls:"SLES12.0SP1"))) {
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
