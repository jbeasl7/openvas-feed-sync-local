# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0533.1");
  script_cve_id("CVE-2020-14803");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:36:52 +0000 (Fri, 23 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0533-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0533-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210533-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181239");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-February/008355.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2021:0533-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

- Update to version jdk8u282 (icedtea 3.18.0)
 * January 2021 CPU (bsc#1181239)
 * Security fixes
 + JDK-8247619: Improve Direct Buffering of Characters (CVE-2020-14803)
 * Import of OpenJDK 8 u282 build 01
 + JDK-6962725: Regtest javax/swing/JFileChooser/6738668/
 /bug6738668.java fails under Linux
 + JDK-8025936: Windows .pdb and .map files does not have proper
 dependencies setup
 + JDK-8030350: Enable additional compiler warnings for GCC
 + JDK-8031423: Test java/awt/dnd/DisposeFrameOnDragCrash/
 /DisposeFrameOnDragTest.java fails by Timeout on Windows
 + JDK-8036122: Fix warning 'format not a string literal'
 + JDK-8051853: new
 URI('x/').resolve('..').getSchemeSpecificPart() returns null!
 + JDK-8132664: closed/javax/swing/DataTransfer/DefaultNoDrop/
 /DefaultNoDrop.java locks on Windows
 + JDK-8134632: Mark javax/sound/midi/Devices/
 /InitializationHang.java as headful
 + JDK-8148854: Class names 'SomeClass' and 'LSomeClass,'
 treated by JVM as an equivalent
 + JDK-8148916: Mark bug6400879.java as intermittently failing
 + JDK-8148983: Fix extra comma in changes for JDK-8148916
 + JDK-8160438: javax/swing/plaf/nimbus/8057791/bug8057791.java
 fails
 + JDK-8165808: Add release barriers when allocating objects
 with concurrent collection
 + JDK-8185003: JMX: Add a version of
 ThreadMXBean.dumpAllThreads with a maxDepth argument
 + JDK-8202076: test/jdk/java/io/File/WinSpecialFiles.java on
 windows with VS2017
 + JDK-8207766: [testbug] Adapt tests for Aix.
 + JDK-8212070: Introduce diagnostic flag to abort VM on failed
 JIT compilation
 + JDK-8213448: [TESTBUG] enhance jfr/jvm/TestDumpOnCrash
 + JDK-8215727: Restore JFR thread sampler loop to old /
 previous behavior
 + JDK-8220657: JFR.dump does not work when filename is set
 + JDK-8221342: [TESTBUG] Generate Dockerfile for docker testing
 + JDK-8224502: [TESTBUG] JDK docker test TestSystemMetrics.java
 fails with access issues and OOM
 + JDK-8231209: [REDO] ThreadMXBean::getThreadAllocatedBytes()
 can be quicker for self thread
 + JDK-8231968: getCurrentThreadAllocatedBytes default
 implementation s/b getThreadAllocatedBytes
 + JDK-8232114: JVM crashed at imjpapi.dll in native code
 + JDK-8234270: [REDO] JDK-8204128 NMT might report incorrect
 numbers for Compiler area
 + JDK-8234339: replace JLI_StrTok in java_md_solinux.c
 + JDK-8238448: RSASSA-PSS signature verification fail when
 using certain odd key sizes
 + JDK-8242335: Additional Tests for RSASSA-PSS
 + JDK-8244225: stringop-overflow warning on strncpy call from
 compile_the_world_in
 + JDK-8245400: Upgrade to LittleCMS 2.11
 + JDK-8248214: Add paddings for TaskQueueSuper to reduce
 false-sharing cache contention
 + JDK-8249176: Update GlobalSignR6CA test certificates
 + JDK-8250665: Wrong translation for the month name of May in
 ar_JO,LB,SY
 + JDK-8250928: JFR: Improve hash algorithm for stack ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.282~27.56.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.282~27.56.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.282~27.56.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.282~27.56.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.282~27.56.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.282~27.56.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.282~27.56.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.282~27.56.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.282~27.56.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.282~27.56.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.282~27.56.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.282~27.56.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.282~27.56.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.282~27.56.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.282~27.56.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.282~27.56.2", rls:"SLES12.0SP5"))) {
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
