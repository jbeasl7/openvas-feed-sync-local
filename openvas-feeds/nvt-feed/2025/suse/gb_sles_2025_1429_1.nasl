# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1429.1");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:15:54 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1429-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251429-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241276");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039130.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk' package(s) announced via the SUSE-SU-2025:1429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-21-openjdk fixes the following issues:

Update to upstream tag jdk-21.0.7+6 (April 2025 CPU)

CVEs fixed:

+ CVE-2025-21587: Fixed JSSE unauthorized access, deletion or modification of critical data (bsc#1241274)
+ CVE-2025-30691: Fixed Oracle Java SE Compiler Unauthorized Data Access (bsc#1241275)
+ CVE-2025-30698: Fixed Oracle Java 2D unauthorized data access and DoS (bsc#1241276)

Changes:

 + JDK-8198237: [macos] Test java/awt/Frame/
 /ExceptionOnSetExtendedStateTest/
 /ExceptionOnSetExtendedStateTest.java fails
 + JDK-8211851: (ch) java/nio/channels/AsynchronousSocketChannel/
 /StressLoopback.java times out (aix)
 + JDK-8226933: [TEST_BUG]GTK L&F: There is no swatches or RGB
 tab in JColorChooser
 + JDK-8226938: [TEST_BUG]GTK L&F: There is no Details button in
 FileChooser Dialog
 + JDK-8227529: With malformed --app-image the error messages
 are awful
 + JDK-8277240: java/awt/Graphics2D/ScaledTransform/
 /ScaledTransform.java dialog does not get disposed
 + JDK-8283664: Remove jtreg tag manual=yesno for
 java/awt/print/PrinterJob/PrintTextTest.java
 + JDK-8286875: ProgrammableUpcallHandler::on_entry/on_exit
 access thread fields from native
 + JDK-8293345: SunPKCS11 provider checks on PKCS11 Mechanism
 are problematic
 + JDK-8294316: SA core file support is broken on macosx-x64
 starting with macOS 12.x
 + JDK-8295159: DSO created with -ffast-math breaks Java
 floating-point arithmetic
 + JDK-8302111: Serialization considerations
 + JDK-8304701: Request with timeout aborts later in-flight
 request on HTTP/1.1 cxn
 + JDK-8309841: Jarsigner should print a warning if an entry is
 removed
 + JDK-8311546: Certificate name constraints improperly
 validated with leading period
 + JDK-8312570: [TESTBUG] Jtreg compiler/loopopts/superword/
 /TestDependencyOffsets.java fails on 512-bit SVE
 + JDK-8313633: [macOS] java/awt/dnd/NextDropActionTest/
 /NextDropActionTest.java fails with java.lang.RuntimeException:
 wrong next drop action!
 + JDK-8313905: Checked_cast assert in CDS compare_by_loader
 + JDK-8314752: Use google test string comparison macros
 + JDK-8314909: tools/jpackage/windows/Win8282351Test.java fails
 with java.lang.AssertionError: Expected [0]. Actual [1618]:
 + JDK-8315486: vmTestbase/nsk/jdwp/ThreadReference/
 /ForceEarlyReturn/forceEarlyReturn002/forceEarlyReturn002.java
 timed out
 + JDK-8315825: Open some swing tests
 + JDK-8315882: Open some swing tests 2
 + JDK-8315883: Open source several Swing JToolbar tests
 + JDK-8315952: Open source several Swing JToolbar JTooltip
 JTree tests
 + JDK-8316056: Open source several Swing JTree tests
 + JDK-8316146: Open some swing tests 4
 + JDK-8316149: Open source several Swing JTree JViewport
 KeyboardManager tests
 + JDK-8316218: Open some swing tests 5
 + JDK-8316371: Open some swing tests 6
 + JDK-8316627: JViewport Test headless failure
 + JDK-8316885: jcmd: Compiler.CodeHeap_Analytics cmd ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-21-openjdk' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.7.0~150600.3.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.7.0~150600.3.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.7.0~150600.3.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.7.0~150600.3.12.1", rls:"SLES15.0SP6"))) {
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
