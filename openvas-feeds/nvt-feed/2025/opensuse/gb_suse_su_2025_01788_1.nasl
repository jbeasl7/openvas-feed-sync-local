# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01788.1");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698", "CVE-2025-4447");
  script_tag(name:"creation_date", value:"2025-06-04 04:09:46 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 16:19:49 +0000 (Fri, 05 Sep 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01788-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01788-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501788-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243429");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/039482.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2025:01788-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

Update to Java 8.0 Service Refresh 8 Fix Pack 45.

Security issues fixed:

- Oracle April 15 2025 CPU (bsc#1242208)

 * CVE-2025-21587: unauthorized access, deletion and modification of critical data via the JSSE component
 (bsc#1241274).
 * CVE-2025-30691: unauthorized access to data via the Compiler component (bsc#1241275).
 * CVE-2025-30698: unauthorized access to data and ability to cause a partial DoS via the 2D component (bsc#1241276).

- IBM Security Update May 2025

 * CVE-2025-4447: stack based buffer overflow in Eclipse OpenJ9 through modification of file that is read when the JVM
 starts (bsc#1243429).

Other changes and issues fixed:

- Security:

 * Avoid memory leak during aes cipher initialization operations
 for IBMJCEPlus and IBMJCEPlusProviders provider.
 * Changing the default of the com.ibm.security.spnego.msinterop
 property from true to false.
 * Deserializing a com.ibm.crypto.provider.rsaprivatecrtkey object
 causes a java.io.invalidobjectexception to be thrown.
 * Failed to read private key from a JKS keystore, specified as
 JCEKS keystore.
 * HTTPS channel binding support.
 * Keytool listing PKCS12 keystore issue.
 * On Linux systems, use gcc11.2 to compile IBM PKCS11 library.
 * Support has been added to the IBM Java XMLDSigRI security provider
 for the EdDSA (Edwards-curve Digital Signature Algorithm).
 * Updates to XDH Key Agreement, AESGCM Algorithms in IBMJCEPlus
 and IBMJCEPlusFIPS providers.

- Class Libraries:

 * Update timezone information to the latest tzdata2025a.

- Java Virtual Machine:

 * A SIGSEGV/GPF event received while processing verifyerror.
 * Crash while resolving MethodHandleNatives.
 * NoSuchMethodException or NoClassDefFoundError when loading classes.

- JIT Compiler:

 * Assert in the JIT Compiler, badILOp.
 * Reduced MD5 performance.");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-32bit", rpm:"java-1_8_0-ibm-32bit~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-demo", rpm:"java-1_8_0-ibm-demo~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel-32bit", rpm:"java-1_8_0-ibm-devel-32bit~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-src", rpm:"java-1_8_0-ibm-src~1.8.0_sr8.45~150000.3.101.1", rls:"openSUSELeap15.6"))) {
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
