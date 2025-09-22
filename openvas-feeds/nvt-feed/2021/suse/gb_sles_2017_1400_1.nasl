# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1400.1");
  script_cve_id("CVE-2017-3289", "CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3512", "CVE-2017-3514", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-04 17:49:35 +0000 (Thu, 04 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1400-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1400-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171400-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034849");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002920.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2017:1400-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:

- Update to 2.6.10 - OpenJDK 7u141 (bsc#1034849)
* Security fixes
 - S8163520, CVE-2017-3509: Reuse cache entries
 - S8163528, CVE-2017-3511: Better library loading
 - S8165626, CVE-2017-3512: Improved window framing
 - S8167110, CVE-2017-3514: Windows peering issue
 - S8169011, CVE-2017-3526: Resizing XML parse trees
 - S8170222, CVE-2017-3533: Better transfers of files
 - S8171121, CVE-2017-3539: Enhancing jar checking
 - S8171533, CVE-2017-3544: Better email transfer
 - S8172299: Improve class processing
 * New features
 - PR3347: jstack.stp should support AArch64
 * Import of OpenJDK 7 u141 build 0
 - S4717864: setFont() does not update Fonts of Menus already on
 screen
 - S6474807: (smartcardio) CardTerminal.connect() throws
 CardException instead of CardNotPresentException
 - S6518907: cleanup IA64 specific code in Hotspot
 - S6869327: Add new C2 flag to keep safepoints in counted loops.
 - S7112912: Message 'Error occurred during initialization of
 VM' on boxes with lots of RAM
 - S7124213: [macosx] pack() does ignore size of a component,
 doesn't on the other platforms
 - S7124219: [macosx] Unable to draw images to fullscreen
 - S7124552: [macosx] NullPointerException in getBufferStrategy()
 - S7148275: [macosx] setIconImages() not working correctly
 (distorted icon when minimized)
 - S7154841: [macosx] Popups appear behind taskbar
 - S7155957:
 closed/java/awt/MenuBar/MenuBarStress1/MenuBarStress1.java
 hangs on win 64 bit with jdk8
 - S7160627: [macosx] TextArea has wrong initial size
 - S7167293: FtpURLConnection connection leak on
 FileNotFoundException
 - S7168851: [macosx] Netbeans crashes in
 CImage.nativeCreateNSImageFromArray
 - S7197203: sun/misc/URLClassPath/ClassnameCharTest.sh failed,
 compile error
 - S8005255: [macosx] Cleanup warnings in sun.lwawt
 - S8006088: Incompatible heap size flags accepted by VM
 - S8007295: Reduce number of warnings in awt classes
 - S8010722: assert: failed: heap size is too big for compressed
 oops
 - S8011059: [macosx] Support automatic @2x images loading on
 Mac OS X
 - S8014058: Regression tests for 8006088
 - S8014489:
 tests/gc/arguments/Test(Serial<pipe>CMS<pipe>Parallel<pipe>G1)HeapSizeFlags
 jtreg tests invoke wrong class
 - S8016302: Change type of the number of GC workers to unsigned
 int (2)
 - S8024662: gc/arguments/TestUseCompressedOopsErgo.java does
 not compile.
 - S8024669: Native OOME when allocating after changes to
 maximum heap supporting Coops sizing on sparcv9
 - S8024926: [macosx] AquaIcon HiDPI support
 - S8025974: l10n for policytool
 - S8027025: [macosx] getLocationOnScreen returns 0 if parent
 invisible
 - S8028212: Custom cursor HiDPI support
 - S8028471: PPC64 (part 215): opto: Extend ImplicitNullCheck
 optimization.
 - S8031573: [macosx] Checkmarks of JCheckBoxMenuItems aren't
 rendered in high resolution on Retina
 - S8033534: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.141~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.141~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.141~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.141~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.141~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.141~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.141~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.141~42.1", rls:"SLES12.0SP2"))) {
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
