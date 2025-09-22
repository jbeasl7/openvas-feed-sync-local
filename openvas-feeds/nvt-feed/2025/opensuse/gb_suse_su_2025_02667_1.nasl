# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02667.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-50059", "CVE-2025-50106");
  script_tag(name:"creation_date", value:"2025-08-06 04:21:55 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:40 +0000 (Tue, 15 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02667-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02667-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502667-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041083.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-17-openjdk' package(s) announced via the SUSE-SU-2025:02667-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:

Upgrade to upstream tag jdk-17.0.16+8 (July 2025 CPU):

- CVE-2025-30749: several scenarios can lead to heap corruption (bsc#1246595)
- CVE-2025-30754: incomplete handshake may lead to weakening TLS protections (bsc#1246598)
- CVE-2025-50059: Improve HTTP client header handling (bsc#1246575)
- CVE-2025-50106: Glyph out-of-memory access and crash (bsc#1246584)

Changelog:

 + JDK-4850101: Setting mnemonic to VK_F4 underlines the letter
 S in a button.
 + JDK-5074006: Swing JOptionPane shows </html> tag as a string
 after newline
 + JDK-6956385: URLConnection.getLastModified() leaks file
 handles for jar:file and file: URLs
 + JDK-8024624: [TEST_BUG] [macosx] CTRL+RIGHT(LEFT) doesn't
 move selection on next cell in JTable on Aqua L&F
 + JDK-8042134: JOptionPane bungles HTML messages
 + JDK-8051591: Test
 javax/swing/JTabbedPane/8007563/Test8007563.java fails
 + JDK-8077371: Binary files in JAXP test should be removed
 + JDK-8183348: Better cleanup for
 jdk/test/sun/security/pkcs12/P12SecretKey.java
 + JDK-8196465:
 javax/swing/JComboBox/8182031/ComboPopupTest.java fails on
 Linux
 + JDK-8202100: Merge vm/share/InMemoryJavaCompiler w/
 jdk/test/lib/compiler/InMemoryJavaCompiler
 + JDK-8211400: nsk.share.gc.Memory::getArrayLength returns
 wrong value
 + JDK-8218474: JComboBox display issue with GTKLookAndFeel
 + JDK-8224267: JOptionPane message string with 5000+ newlines
 produces StackOverflowError
 + JDK-8249831: Test sun/security/mscapi/nonUniqueAliases/
 /NonUniqueAliases.java is marked with @ignore
 + JDK-8251505: Use of types in compiler shared code should be
 consistent.
 + JDK-8253440: serviceability/sa/TestJhsdbJstackLineNumbers.java
 failed with 'Didn't find enough line numbers'
 + JDK-8254786: java/net/httpclient/CancelRequestTest.java
 failing intermittently
 + JDK-8256211: assert fired in
 java/net/httpclient/DependentPromiseActionsTest (infrequent)
 + JDK-8258483: [TESTBUG] gtest
 CollectorPolicy.young_scaled_initial_ergo_vm fails if heap is
 too small
 + JDK-8269516: AArch64: Assembler cleanups
 + JDK-8271419: Refactor test code for modifying CDS archive
 contents
 + JDK-8276995: Bug in jdk.jfr.event.gc.collection.TestSystemGC
 + JDK-8277983: Remove unused fields from
 sun.net.www.protocol.jar.JarURLConnection
 + JDK-8279884: Use better file for cygwin source permission
 check
 + JDK-8279894: javax/swing/JInternalFrame/8020708/bug8020708.java
 timeouts on Windows 11
 + JDK-8280468: Crashes in getConfigColormap,
 getConfigVisualId, XVisualIDFromVisual on Linux
 + JDK-8280820: Clean up bug8033699 and bug8075609.java tests:
 regtesthelpers aren't used
 + JDK-8280991: [XWayland] No displayChanged event after
 setDisplayMode call
 + JDK-8281511: java/net/ipv6tests/UdpTest.java fails with
 checkTime failed
 + JDK-8282863: java/awt/FullScreen/FullscreenWindowProps/
 /FullscreenWindowProps.java fails on ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.16.0~150400.3.57.1", rls:"openSUSELeap15.6"))) {
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
