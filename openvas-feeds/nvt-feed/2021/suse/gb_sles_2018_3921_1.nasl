# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3921.1");
  script_cve_id("CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3214");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:33 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-23 13:40:14 +0000 (Tue, 23 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3921-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3921-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183921-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116574");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-November/004894.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2018:3921-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"java-1_7_1-ibm was updated to Java 7.1 Service Refresh 4 Fix Pack 35 (bsc#1116574):

* Consumability

 - IJ10515 AIX JAVA 7.1.3.10 GENERAL PROTECTION FAULT WHEN ATTEMPTING TO USE HEALTH CENTER API

* Class Libraries

 - IJ10934 CVE-2018-13785
 - IJ10935 CVE-2018-3136
 - IJ10895 CVE-2018-3139
 - IJ10932 CVE-2018-3149
 - IJ10894 CVE-2018-3180
 - IJ10933 CVE-2018-3214
 - IJ09315 FLOATING POINT EXCEPTION FROM JAVA.TEXT.DECIMALFORMAT. FORMAT
 - IJ09088 INTRODUCING A NEW PROPERTY FOR TURKEY TIMEZONE FOR PRODUCTS NOT IDENTIFYING TRT
 - IJ08569 JAVA.IO.IOEXCEPTION OCCURS WHEN A FILECHANNEL IS BIGGER THAN 2GB ON AIX PLATFORM
 - IJ10800 REMOVE EXPIRING ROOT CERTIFICATES IN IBM JDK'S CACERTS.

* Java Virtual Machine

 - IJ10931 CVE-2018-3169
 - IV91132 SOME CORE PATTERN SPECIFIERS ARE NOT HANDLED BY THE JVM ON LINUX

* JIT Compiler

 - IJ08205 CRASH WHILE COMPILING
 - IJ07886 INCORRECT CALUCATIONS WHEN USING NUMBERFORMAT.FORMAT() AND BIGDECIMAL.{FLOAT/DOUBLE }VALUE()

* ORB

 - IX90187 CLIENTREQUESTIMPL.REINVO KE FAILS WITH JAVA.LANG.INDEXOUTOFBOUN DSEXCEPTION

* Security

 - IJ10492 'EC KEYSIZE < 384' IS NOT HONORED USING THE 'JDK.TLS.DISABLEDALGORIT HMS' SECURITY PROPERTY
 - IJ10491 AES/GCM CIPHER - AAD NOT RESET TO UN-INIT STATE AFTER DOFINAL( ) AND INIT( )
 - IJ08442 HTTP PUBLIC KEY PINNING FINGERPRINT,PROBLEM WITH CONVERTING TO JKS KEYSTORE
 - IJ09107 IBMPKCS11IMPL CRYPTO PROVIDER - INTERMITTENT ERROR WITH SECP521R1 SIGNATURE ON Z/OS
 - IJ10136 IBMPKCS11IMPL - INTERMITTENT ERROR WITH SECP521R1 SIG ON Z/OS AND Z/LINUX
 - IJ08530 IBMPKCS11IMPL PROVIDER USES THE WRONG RSA CIPHER MECHANISM FOR THE RSA/ECB/PKCS1PADDING CIPHER
 - IJ08723 JAAS THROWS A 'ARRAY INDEX OUT OF RANGE' EXCEPTION
 - IJ08704 THE SECURITY PROPERTY 'JDK.CERTPATH.DISABLEDAL GORITHMS' IS MISTAKENLY BEING USED TO FILTER JAR SIGNING ALGORITHMS

* z/OS Extensions

 - PH01244 OUTPUT BUFFER TOO SHORT FOR GCM MODE ENCRYPTION USING IBMJCEHYBRID");

  script_tag(name:"affected", value:"'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr4.35~26.32.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr4.35~26.32.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr4.35~26.32.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr4.35~26.32.1", rls:"SLES11.0SP4"))) {
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
