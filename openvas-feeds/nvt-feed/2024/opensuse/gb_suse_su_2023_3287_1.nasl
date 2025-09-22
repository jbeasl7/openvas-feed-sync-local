# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833154");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-22006", "CVE-2023-22036", "CVE-2023-22041", "CVE-2023-22044", "CVE-2023-22045", "CVE-2023-22049", "CVE-2023-25193");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-13 14:53:46 +0000 (Mon, 13 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:54:52 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2023:3287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3287-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CECF3ZVVCSCWYFXMMRQWRCDFRENQUVMU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2023:3287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

  Updated to jdk-11.0.20+8 (July 2023 CPU):

  * CVE-2023-22006: Fixed vulnerability in the network component (bsc#1213473).

  * CVE-2023-22036: Fixed vulnerability in the utility component (bsc#1213474).

  * CVE-2023-22041: Fixed vulnerability in the hotspot component (bsc#1213475).

  * CVE-2023-22044: Fixed vulnerability in the hotspot component (bsc#1213479).

  * CVE-2023-22045: Fixed vulnerability in the hotspot component (bsc#1213481).

  * CVE-2023-22049: Fixed vulnerability in the libraries component
      (bsc#1213482).

  * CVE-2023-25193: Fixed vulnerability in the embedded harfbuzz module
      (bsc#1207922).

  * JDK-8298676: Enhanced Look and Feel

  * JDK-8300285: Enhance TLS data handling

  * JDK-8300596: Enhance Jar Signature validation

  * JDK-8301998, JDK-8302084: Update HarfBuzz to 7.0.1

  * JDK-8302475: Enhance HTTP client file downloading

  * JDK-8302483: Enhance ZIP performance

  * JDK-8303376: Better launching of JDI

  * JDK-8304468: Better array usages

  * JDK-8305312: Enhanced path handling

  * JDK-8308682: Enhance AES performance

  Bugfixes:

  * JDK-8171426: java/lang/ProcessBuilder/Basic.java failed with Stream closed

  * JDK-8178806: Better exception logging in crypto code

  * JDK-8187522: test/sun/net/ftp/FtpURLConnectionLeak.java timed out

  * JDK-8209167: Use CLDR's time zone mappings for Windows

  * JDK-8209546: Make sun/security/tools/keytool/autotest.sh to support macosx

  * JDK-8209880: tzdb.dat is not reproducibly built

  * JDK-8213531: Test javax/swing/border/TestTitledBorderLeak.java fails

  * JDK-8214459: NSS source should be removed

  * JDK-8214807: Improve handling of very old class files

  * JDK-8215015: [TESTBUG] remove unneeded -Xfuture option from tests

  * JDK-8215575: C2 crash: assert(get_instanceKlass()- is_loaded()) failed: must
      be at least loaded

  * JDK-8220093: Change to GCC 8.2 for building on Linux at Oracle

  * JDK-8227257: javax/swing/JFileChooser/4847375/bug4847375.java fails with
      AssertionError

  * JDK-8232853: AuthenticationFilter.Cache::remove may throw
      ConcurrentModificationException

  * JDK-8243936: NonWriteable system properties are actually writeable

  * JDK-8246383: NullPointerException in JceSecurity.getVerificationResult when
      using Entrust provider

  * JDK-8248701: On Windows generated modules-deps.gmk can contain backslash-r
      (CR) characters

  * JDK-8257856: Make ClassFileVersionsTest.java robust to JDK version updates

  * JDK-8259530: Gener ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.20.0~150000.3.99.1", rls:"openSUSELeap15.5"))) {
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