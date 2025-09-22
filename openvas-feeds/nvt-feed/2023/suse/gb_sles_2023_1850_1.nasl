# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1850.1");
  script_cve_id("CVE-2022-21426", "CVE-2023-21830", "CVE-2023-21835", "CVE-2023-21843");
  script_tag(name:"creation_date", value:"2023-04-17 04:17:19 +0000 (Mon, 17 Apr 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-18 00:15:13 +0000 (Wed, 18 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1850-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1850-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231850-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208480");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-April/028817.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2023:1850-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2023-21830: Fixed improper restrictions in CORBA deserialization (bsc#1207249).
 - CVE-2023-21835: Fixed handshake DoS attack against DTLS connections (bsc#1207246).
 - CVE-2023-21843: Fixed soundbank URL remote loading (bsc#1207248).

 * New Features/Enhancements:
 - Add RSA-PSS signature to IBMJCECCA.
 * Defect Fixes:
 - IJ45437 Service, Build, Packaging and Deliver: Getting
 FIPSRUNTIMEEXCEPTION when calling java code:
 MESSAGEDIGEST.GETINSTANCE('SHA256', 'IBMJCEFIPS'), in MAC
 - IJ45272 Class Libraries: Fix security vulnerability CVE-2023-21843
 - IJ45280 Class Libraries: Update timezone information to the
 latest TZDATA2022F
 - IJ44896 Class Libraries: Update timezone information to the
 latest TZDATA2022G
 - IJ45436 Java Virtual Machine: Stack walking code gets into
 endless loop, hanging the application
 - IJ44079 Java Virtual Machine: When -DFILE.ENCODING is specified
 multiple times on the same command line the first option takes
 precedence instead of the last
 - IJ44532 JIT Compiler: Java JIT: Crash in DECREFERENCECOUNT()
 due to a NULL pointer
 - IJ44596 JIT Compiler: Java JIT: Invalid hard-coding of static
 final field object properties
 - IJ44107 JIT Compiler: JIT publishes new object reference to other
 threads without executing a memory flush
 - IX90193 ORB: Fix security vulnerability CVE-2023-21830
 - IJ44267 Security: 8273553: SSLENGINEIMPL.CLOSEINBOUND also has
 similar error of JDK-8253368
 - IJ45148 Security: code changes for tech preview
 - IJ44621 Security: Computing Diffie-Hellman secret repeatedly,
 using IBMJCEPLUS, causes a small memory leak
 - IJ44172 Security: Disable SHA-1 signed jars for EA
 - IJ44040 Security: Generating Diffie-Hellman key pairs repeatedly,
 using IBMJCEPLUS, Causes a small memory leak
 - IJ45200 Security: IBMJCEPLUS provider, during CHACHA20-POLY1305
 crypto operations, incorrectly throws an ILLEGALSTATEEXCEPTION
 - IJ45182 Security: IBMJCEPLUS provider fails in RSAPSS and ECDSA
 during signature operations resulting in Java cores
 - IJ45201 Security: IBMJCEPLUS provider failures (two) with AESGCM algorithm
 - IJ45202 Security: KEYTOOL NPE if signing certificate does not contain
 a SUBJECTKEYIDENTIFIER extension
 - IJ44075 Security: PKCS11KEYSTORE.JAVA - DOESPUBLICKEYMATCHPRIVATEKEY()
 method uses SHA1XXXX signature algorithms to match private and public keys
 - IJ45203 Security: RSAPSS multiple names for KEYTYPE
 - IJ43920 Security: The PKCS12 keystore update and the PBES2 support
 - IJ40002 XML: Fix security vulnerability CVE-2022-21426");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.0~150000.3.71.1", rls:"SLES15.0SP3"))) {
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
