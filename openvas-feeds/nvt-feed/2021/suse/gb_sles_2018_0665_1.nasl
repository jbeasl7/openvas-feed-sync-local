# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0665.1");
  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2638", "CVE-2018-2639", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-01 14:31:05 +0000 (Thu, 01 Feb 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0665-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0665-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180665-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955131");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003808.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2018:0665-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-2639 CVE-2018-2638 CVE-2018-2633 CVE-2018-2637
 CVE-2018-2634 CVE-2018-2582 CVE-2018-2641 CVE-2018-2618
 CVE-2018-2603 CVE-2018-2599 CVE-2018-2602 CVE-2018-2678
 CVE-2018-2677 CVE-2018-2663 CVE-2018-2588 CVE-2018-2579

* Defect fixes:

 - IJ02608 Class Libraries: Change of namespace definitions with
 handlers that implement javax.xml.ws.handler.soap.soaphandler
 - IJ04280 Class Libraries: Deploy Upgrade to Oracle level 8u161-b12
 - IJ03390 Class Libraries: JCL Upgrade to Oracle level 8u161-b12
 - IJ04001 Class Libraries: Performance improvement with child
 process on AIX
 - IJ04281 Class Libraries: Startup time increase after applying
 apar IV96905
 - IJ03822 Class Libraries: Update timezone information to tzdata2017c
 - IJ03440 Java Virtual Machine: Assertion failure during class creation
 - IJ03717 Java Virtual Machine: Assertion for gencon with concurrent
 scavenger on ZOS64
 - IJ03513 Java Virtual Machine: Assertion in concurrent scavenger if
 initial heap memory size -Xms is set too low
 - IJ03994 Java Virtual Machine: Class.getmethods() does not return
 all methods
 - IJ03413 Java Virtual Machine: Hang creating thread after redefining
 classes
 - IJ03852 Java Virtual Machine: ICH408I message when groupaccess is
 specified with -xshareclasses
 - IJ03716 Java Virtual Machine: java/lang/linkageerror from
 sun/misc/unsafe.definean onymousclass()
 - IJ03116 Java Virtual Machine: java.fullversion string contains an
 extra space
 - IJ03347 Java Virtual Machine: java.lang.IllegalStateException in
 related class MemoryMXBean
 - IJ03878 Java Virtual Machine: java.lang.StackOverflowError is thrown
 when custom security manager in place
 - IJ03605 Java Virtual Machine: Legacy security for com.ibm.jvm.dump,
 trace, log was not enabled by default
 - IJ04248 JIT Compiler: ArrayIndexOutOfBoundsException is thrown when
 converting BigDecimal to String
 - IJ04250 JIT Compiler: Assertion failure with concurrentScavenge on Z14
 - IJ03606 JIT Compiler: Java crashes with -version
 - IJ04251 JIT Compiler: JIT compiled method that takes advantage of
 AutoSIMD produces an incorrect result on x86
 - IJ03854 JIT Compiler: JVM info message appears in stdout
 - IJ03607 JIT Compiler: Result String contains a redundant dot when
 converted from BigDecimal with 0 on all platforms
 - IX90185 ORB: Upgrade ibmcfw.jar to version O1800.01
 - IJ03715 Security: Add additional support for the IBMJCEPlus provider,
 add support for new IBMJCEPlusFIPS provider
 - IJ03800 Security: A fix in CMS provider for KDB integrity
 - IJ04282 Security: Change in location and default of jurisdiction
 policy files
 - IJ03853 Security: IBMCAC provider does not support SHA224
 - IJ02679 Security: IBMPKCS11Impl - Bad sessions are being allocated
 internally
 - IJ02706 Security: IBMPKCS11Impl - Bad sessions are being allocated
 internally
 - IJ03552 Security: IBMPKCS11Impl - ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr5.10~30.16.1", rls:"SLES12.0SP3"))) {
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
