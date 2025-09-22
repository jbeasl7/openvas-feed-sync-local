# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1490.1");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_tag(name:"creation_date", value:"2025-05-12 04:09:04 +0000 (Mon, 12 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:15:54 +0000 (Tue, 15 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1490-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1490-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251490-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241276");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-May/020782.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-17-openjdk' package(s) announced via the SUSE-SU-2025:1490-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:

Update to upstream tag jdk-17.0.15+6 (April 2025 CPU)

CVEs:

+ CVE-2025-21587: Fixed JSSE unauthorized access, deletion or modification of critical data (bsc#1241274)
+ CVE-2025-30691: Fixed Oracle Java SE Compiler Unauthorized Data Access (bsc#1241275)
+ CVE-2025-30698: Fixed Oracle Java 2D unauthorized data access and DoS (bsc#1241276)

Changes:

 + JDK-6355567: AdobeMarkerSegment causes failure to read
 valid JPEG
 + JDK-8065099: [macos] javax/swing/PopupFactory/6276087/
 /NonOpaquePopupMenuTest.java fails: no background shine
 through
 + JDK-8179502: Enhance OCSP, CRL and Certificate Fetch
 Timeouts
 + JDK-8198237: [macos] Test java/awt/Frame/
 /ExceptionOnSetExtendedStateTest/
 /ExceptionOnSetExtendedStateTest.java fails
 + JDK-8198666: Many java/awt/Modal/OnTop/ test fails on mac
 + JDK-8208565: [TEST_BUG] javax/swing/PopupFactory/6276087/
 /NonOpaquePopupMenuTest.java throws NPE
 + JDK-8226933: [TEST_BUG]GTK L&F: There is no swatches or
 RGB tab in JColorChooser
 + JDK-8226938: [TEST_BUG]GTK L&F: There is no Details
 button in FileChooser Dialog
 + JDK-8266435: WBMPImageReader.read() should not truncate
 the input stream
 + JDK-8267893: Improve jtreg test failure handler do get
 native/mixed stack traces for cores and live processes
 + JDK-8270961: [TESTBUG] Move GotWrongOOMEException into
 vm.share.gc package
 + JDK-8274893: Update java.desktop classes to use
 try-with-resources
 + JDK-8276202: LogFileOutput.invalid_file_vm asserts when
 being executed from a read only working directory
 + JDK-8277240: java/awt/Graphics2D/ScaledTransform/
 /ScaledTransform.java dialog does not get disposed
 + JDK-8281234: The -protected option is not always checked
 in keytool and jarsigner
 + JDK-8282314: nsk/jvmti/SuspendThread/suspendthrd003 may
 leak memory
 + JDK-8283387: [macos] a11y : Screen magnifier does not
 show selected Tab
 + JDK-8283404: [macos] a11y : Screen magnifier does not
 show JMenu name
 + JDK-8283664: Remove jtreg tag manual=yesno for
 java/awt/print/PrinterJob/PrintTextTest.java
 + JDK-8286779: javax.crypto.CryptoPolicyParser#isConsistent
 always returns 'true'
 + JDK-8286875: ProgrammableUpcallHandler::on_entry/on_exit
 access thread fields from native
 + JDK-8290400: Must run exe installers in jpackage jtreg
 tests without UI
 + JDK-8292588: [macos] Multiscreen/MultiScreenLocationTest/
 /MultiScreenLocationTest.java: Robot.mouseMove test failed on
 Screen #0
 + JDK-8292704: sun/security/tools/jarsigner/compatibility/
 /Compatibility.java use wrong key size for EC
 + JDK-8292848: AWT_Mixing and TrayIcon tests fail on el8
 with hard-coded isOel7
 + JDK-8293345: SunPKCS11 provider checks on PKCS11
 Mechanism are problematic
 + JDK-8293412: Remove unnecessary java.security.egd
 overrides
 + JDK-8294067: [macOS] javax/swing/JComboBox/6559152/
 /bug6559152.java Cannot select an item from popup with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-17-openjdk' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.15.0~150400.3.54.1", rls:"openSUSELeap15.6"))) {
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
