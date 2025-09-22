# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2453.1");
  script_cve_id("CVE-2019-17639", "CVE-2020-14556", "CVE-2020-14577", "CVE-2020-14578", "CVE-2020-14579", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-21 02:50:09 +0000 (Tue, 21 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2453-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2453-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202453-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175259");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007336.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2020:2453-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

- Update to Java 8.0 Service Refresh 6 Fix Pack 15 [bsc#1175259, bsc#1174157]
 CVE-2020-14577 CVE-2020-14578 CVE-2020-14579 CVE-2020-14581
 CVE-2020-14556 CVE-2020-14621 CVE-2020-14593 CVE-2020-14583
 CVE-2019-17639
 * Class Libraries:
 - JAVA.UTIL.ZIP.DEFLATER OPERATIONS THROW JAVA.LANG.INTERNALERROR
 - JAVA 8 DECODER OBJECTS CONSUME A LARGE AMOUNT OF JAVA HEAP
 - TRANSLATION MESSAGES UPDATE FOR JCL
 - UPDATE TIMEZONE INFORMATION TO TZDATA2020A
 * Java Virtual Machine:
 - IBM JAVA REGISTERS A HANDLER BY DEFAULT FOR SIGABRT
 - LARGE MEMORY FOOTPRINT HELD BY TRACECONTEXT OBJECT
 * JIT Compiler:
 - CRASH IN THE INTERPRETER AFTER OSR FROM INLINED SYNCHRONIZED METHOD
 IN DEBUGGING MODE
 - INTERMITTENT ASSERTION FAILURE REPORTED
 - CRASH IN RESOLVECLASSREF() DURING AOT LOAD
 - JIT CRASH DURING CLASS UNLOADING IN J9METHOD_HT::ONCLASSUNLOADING()
 - SEGMENTATION FAULT WHILE COMPILING A METHOD
 - UNEXPECTED CLASSCASTEXCEPTION THROWN IN HIGH LEVEL PARALLEL
 APPLICATION ON IBM Z PLATFORM
 * Security:
 - CERTIFICATEEXCEPTION OCCURS WHEN FILE.ENCODING PROPERTY SET TO
 NON DEFAULT VALUE
 - CHANGES TO IBMJCE AND IBMJCEPLUS PROVIDERS
 - IBMJCEPLUS FAILS, WHEN THE SECURITY MANAGER IS ENABLED, WITH
 DEFAULT PERMISSIONS, SPECIFIED IN JAVA.POLICY FILE
 - IN CERTAIN INSTANCES, IBMJCEPLUS PROVIDER THROWS EXCEPTION FROM
 KEYFACTORY CLASS");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.15~3.41.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.15~3.41.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.15~3.41.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr6.15~3.41.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.15~3.41.1", rls:"SLES15.0"))) {
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
