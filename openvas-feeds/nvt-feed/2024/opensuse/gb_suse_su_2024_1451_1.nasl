# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856117");
  script_cve_id("CVE-2024-21011", "CVE-2024-21068", "CVE-2024-21085", "CVE-2024-21094");
  script_tag(name:"creation_date", value:"2024-05-07 01:05:44 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-16 22:15:29 +0000 (Tue, 16 Apr 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1451-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241451-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222986");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/035112.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2024:1451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

- CVE-2024-21011: Fixed denial of service due to long Exception message logging (JDK-8319851,bsc#1222979)
- CVE-2024-21068: Fixed integer overflow in C1 compiler address generation (JDK-8322122,bsc#1222983)
- CVE-2024-21085: Fixed Pack200 excessive memory allocation (JDK-8322114,bsc#1222984)
- CVE-2024-21094: Fixed unauthorized data modification due to C2 compilation failure with 'Exceeded _node_regs array' (JDK-8317507,JDK-8325348,bsc#1222986)

Other fixes:
- Update to version jdk8u412 (icedtea-3.31.0) (April 2024 CPU)
 * Security fixes
 + JDK-8318340: Improve RSA key implementations
 * Import of OpenJDK 8 u412 build 08
 + JDK-8011180: Delete obsolete scripts
 + JDK-8016451: Scary messages emitted by
 build.tools.generatenimbus.PainterGenerator during build
 + JDK-8021961: setAlwaysOnTop doesn't behave correctly in
 Linux/Solaris under certain scenarios
 + JDK-8023735: [TESTBUG][macosx]
 runtime/XCheckJniJsig/XCheckJSig.java fails on MacOS X
 + JDK-8074860: Structured Exception Catcher missing around
 CreateJavaVM on Windows
 + JDK-8079441: Intermittent failures on Windows with 'Unexpected
 exit from test [exit code: 1080890248]' (0x406d1388)
 + JDK-8155590: Dubious collection management in
 sun.net.www.http.KeepAliveCache
 + JDK-8168518: rcache interop with krb5-1.15
 + JDK-8183503: Update hotspot tests to allow for unique test
 classes directory
 + JDK-8186095: upgrade to jtreg 4.2 b08
 + JDK-8186199: [windows] JNI_DestroyJavaVM not covered by SEH
 + JDK-8192931: Regression test
 java/awt/font/TextLayout/CombiningPerf.java fails
 + JDK-8208655: use JTreg skipped status in hotspot tests
 + JDK-8208701: Fix for JDK-8208655 causes test failures in CI
 tier1
 + JDK-8208706: compiler/tiered/
 /ConstantGettersTransitionsTest.java fails to compile
 + JDK-8213410: UseCompressedOops requirement check fails fails
 on 32-bit system
 + JDK-8222323: ChildAlwaysOnTopTest.java fails with
 'RuntimeException: Failed to unset alwaysOnTop'
 + JDK-8224768: Test ActalisCA.java fails
 + JDK-8251155: HostIdentifier fails to canonicalize hostnames
 starting with digits
 + JDK-8251551: Use .md filename extension for README
 + JDK-8268678: LetsEncryptCA.java test fails as Let's Encrypt
 Authority X3 is retired
 + JDK-8270280: security/infra/java/security/cert/
 /CertPathValidator/certification/LetsEncryptCA.java OCSP
 response error
 + JDK-8270517: Add Zero support for LoongArch
 + JDK-8272708: [Test]: Cleanup: test/jdk/security/infra/java/
 /security/cert/CertPathValidator/certification/BuypassCA.java
 no longer needs ocspEnabled
 + JDK-8276139: TestJpsHostName.java not reliable, better to
 expand HostIdentifierCreate.java test
 + JDK-8288132: Update test artifacts in QuoVadis CA interop
 tests
 + JDK-8297955: LDAP CertStore should use LdapName and not
 String for DNs
 + JDK-8301310: The SendRawSysexMessage test may cause a JVM
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-accessibility", rpm:"java-1_8_0-openjdk-accessibility~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-javadoc", rpm:"java-1_8_0-openjdk-javadoc~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-src", rpm:"java-1_8_0-openjdk-src~1.8.0.412~150000.3.91.1", rls:"openSUSELeap15.5"))) {
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
