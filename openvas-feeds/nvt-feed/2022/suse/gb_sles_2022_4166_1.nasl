# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4166.1");
  script_cve_id("CVE-2022-21540", "CVE-2022-21541", "CVE-2022-21549", "CVE-2022-21618", "CVE-2022-21619", "CVE-2022-21624", "CVE-2022-21626", "CVE-2022-21628", "CVE-2022-34169", "CVE-2022-39399");
  script_tag(name:"creation_date", value:"2022-11-23 00:15:45 +0000 (Wed, 23 Nov 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-30 15:03:15 +0000 (Tue, 30 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4166-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4166-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224166-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205302");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/013066.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2022:4166-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

- CVE-2022-21626: An unauthenticated attacker with network access via HTTPS can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition (bsc#1204471).
- CVE-2022-21618: An unauthenticated attacker with network access via Kerberos can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition (bsc#1204468).
- CVE-2022-21619: An unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE (bsc#1204473).
- CVE-2022-21628: An unauthenticated attacker with network access via HTTP can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition (bsc#1204472).
- CVE-2022-21624: An unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise (bsc#1204475).
- CVE-2022-39399: An unauthenticated attacker with network access via HTTP can compromise Oracle Java SE, Oracle GraalVM Enterprise Edition (bsc#1204480).
- CVE-2022-21549: Fixed exponentials issue (bsc#1201685).
- CVE-2022-21541: Fixed an improper restriction of MethodHandle.invokeBasic() (bsc#1201692).
- CVE-2022-34169, Fixed an integer truncation issue in Xalan (bsc#1201684).
- CVE-2022-21540: Fixed a class compilation issue (bsc#1201694).


- Update to Java 8.0 Service Refresh 7 Fix Pack 20.
 * Security:
 - The IBM ORB Does Not Support Object-Serialisation Data Filtering
 - Large Allocation In CipherSuite
 - Avoid Evaluating Sslalgorithmconstraints Twice
 - Cache The Results Of Constraint Checks
 - An incorrect ShortBufferException is thrown by IBMJCEPlus,
 IBMJCEPlusFIPS during cipher update operation
 - Disable SHA-1 Signed Jars For Ea
 - JSSE Performance Improvement
 - Oracle Road Map Kerberos Deprecation Of 3DES And RC4 Encryption
 * Java 8/Orb:
 - Upgrade ibmcfw.jar To Version o2228.02
 * Class Libraries:
 - Crash In Libjsor.So During An Rdma Failover
 - High CPU Consumption Observed In ZosEventPort$EventHandlerTask.run
 - Update Timezone Information To The Latest tzdata2022c
 * Jit Compiler:
 - Crash During JIT Compilation
 - Incorrect JIT Optimization Of Java Code
 - Incorrect Return From Class.isArray()
 - Unexpected ClassCastException
 - Performance Regression When Calling VM Helper Code On X86
 * X/Os Extentions:
 - Add RSA-OAEP Cipher Function To IBMJCECCA

- Update to Java 8.0 Service Refresh 7 Fix Pack 16
 * Java Virtual Machine
 - Assertion failure at ClassLoaderRememberedSet.cpp
 - Assertion failure at StandardAccessBarrier.cpp when
 -Xgc:concurrentScavenge is set.
 - GC can have unflushed ownable synchronizer objects which
 can eventually lead to heap corruption and failure when
 -Xgc:concurrentScavenge is set.
 * JIT Compiler:
 - Incorrect JIT optimization of Java code
 - JAVA JIT Power: JIT compile time assert on AIX or LINUXPPC
 * Reliability and Serviceability:
 - javacore with 'kill -3' SIGQUIT signal freezes Java process");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr7.20~150000.3.65.1", rls:"SLES15.0SP2"))) {
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
