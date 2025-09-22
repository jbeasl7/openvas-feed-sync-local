# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03236.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-30761", "CVE-2025-50059", "CVE-2025-50106");
  script_tag(name:"creation_date", value:"2025-09-18 04:08:17 +0000 (Thu, 18 Sep 2025)");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:40 +0000 (Tue, 15 Jul 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03236-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503236-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247754");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041719.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2025:03236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

Update to Java 8.0 Service Refresh 8 Fix Pack 50.

Security issues fixed:

- Oracle July 15 2025 CPU (bsc#1247754).
- CVE-2025-30749: heap corruption allows unauthenticated attacker with network access to compromise and takeover Java
 applications that load and run untrusted code (bsc#1246595).
- CVE-2025-30754: incomplete handshake allows unauthenticated attacker with network access via TLS to gain unauthorized
 update, insert, delete and read access to sensitive data (bsc#1246598).
- CVE-2025-30761: issue in the Scripting component allows unauthenticated attacker with network access to gain
 unauthorized creation, deletion or modification access to critical data (bsc#1246580).
- CVE-2025-50059: issue in the Networking component allows unauthenticated attacker with network access to gain
 unauthorized access to critical data (bsc#1246575).
- CVE-2025-50106: Glyph out-of-memory access allows unauthenticated attacker with network access to compromise and
 takeover Java applications that load and run untrusted code (bsc#1246584).

Other issues fixed.

- Class Libraries:
 - Oracle Security Fix 8348989: Better Glyph drawing.
 - Removal of Baltimore root certificate and TWO CAMERFIRMA root
 CA certificates from CACERTS.
 - Update timezone information to the latest TZDATA2025B.
- Java Virtual Machine:
 - Assertion failure at copyforwardscheme.cpp.
- JIT Compiler:
 - GC assert due to an invalid object reference.
 - SIGILL from JIT compiled method.
 - Unexpected behaviour with very large arrays.
- Security:
 - Deserialization of a serialized RSAPrivateCrtKey is throwing
 an exception.
 - EDDSAsignature fails when doing multiple update.
 - HTTPS channel binding support.
 - IBMJCEPlus provider supports post quantum cryptography algorithms
 ML-KEM (key encapsulation) and ML-DSA (digital signature).
 - Key certificate management: Extended key usage cannot be set
 without having key usage extension in certificate request.
 - MessageDigest.update API does not throw the correct exception.
 - Oracle Security Fix 8349594: Enhance TLS protocol support.
 - Problem getting key in PKCS12 keystore on MAC.
 - TLS support for the EDDSA signature algorithm.
 - Wrong algorithm name returned for EDDSA keys.
- z/OS Extentions:
 - IBMJCEHybridException with hybrid provider in GCM mode.");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.50~30.138.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.50~30.138.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.50~30.138.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.50~30.138.1", rls:"SLES12.0SP5"))) {
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
