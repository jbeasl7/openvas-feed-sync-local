# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1375.1");
  script_cve_id("CVE-2015-0192", "CVE-2015-1931", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:11 +0000 (Tue, 16 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1375-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151375-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938895");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-August/001534.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-ibm' package(s) announced via the SUSE-SU-2015:1375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"java-1_7_0-ibm was updated to fix 21 security issues.

These security issues were fixed:
- CVE-2015-4729: Unspecified vulnerability in Oracle Java SE 7u80 and 8u45 allowed remote attackers to affect confidentiality and integrity via unknown vectors related to Deployment (bsc#938895).
- CVE-2015-4748: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, JRockit R28.3.6, and Java SE Embedded 7u75 and Embedded 8u33 allowed remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Security (bsc#938895).
- CVE-2015-2664: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45 allowed local users to affect confidentiality, integrity, and availability via unknown vectors related to Deployment (bsc#938895).
- CVE-2015-0192: Unspecified vulnerability in IBM Java 8 before SR1, 7 R1 before SR2 FP11, 7 before SR9, 6 R1 before SR8 FP4, 6 before SR16 FP4, and 5.0 before SR16 FP10 allowed remote attackers to gain privileges via unknown vectors related to the Java Virtual Machine (bsc#938895).
- CVE-2015-2613: Unspecified vulnerability in Oracle Java SE 7u80 and 8u45, and Java SE Embedded 7u75 and 8u33 allowed remote attackers to affect confidentiality via vectors related to JCE (bsc#938895).
- CVE-2015-4731: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, Java SE Embedded 7u75, and Java SE Embedded 8u33 allowed remote attackers to affect confidentiality, integrity, and availability via vectors related to JMX (bsc#938895).
- CVE-2015-2637: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, JavaFX 2.2.80, and Java SE Embedded 7u75 and 8u33 allowed remote attackers to affect confidentiality via unknown vectors related to 2D (bsc#938895).
- CVE-2015-4733: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and 8u33 allowed remote attackers to affect confidentiality, integrity, and availability via vectors related to RMI (bsc#938895).
- CVE-2015-4732: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and 8u33 allowed remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries, a different vulnerability than CVE-2015-2590 (bsc#938895).
- CVE-2015-2621: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and 8u33, allowed remote attackers to affect confidentiality via vectors related to JMX (bsc#938895).
- CVE-2015-2619: Unspecified vulnerability in Oracle Java SE 7u80 and 8u45, JavaFX 2.2.80, and Java SE Embedded 7u75 and 8u33 allowed remote attackers to affect confidentiality via unknown vectors related to 2D (bsc#938895).
- CVE-2015-2590: Unspecified vulnerability in Oracle Java SE 6u95, 7u80, and 8u45, and Java SE Embedded 7u75 and 8u33 allowed remote attackers to affect confidentiality, integrity, and availability via ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_0-ibm' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr9.10~9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr9.10~9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-devel", rpm:"java-1_7_0-ibm-devel~1.7.0_sr9.10~9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr9.10~9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr9.10~9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr9.10~9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr9.10~9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr9.10~9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr9.10~9.1", rls:"SLES11.0SP3"))) {
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
