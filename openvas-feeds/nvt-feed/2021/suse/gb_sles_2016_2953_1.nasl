# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2953.1");
  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-27 18:39:36 +0000 (Thu, 27 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2953-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2953-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162953-1.html");
  script_xref(name:"URL", value:"http://icedtea.classpath.org/bugzilla/show_bug.cgi?id=2942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005528");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002431.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2016:2953-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:

- Update to 2.6.8 - OpenJDK 7u121
 * Security fixes
 + S8151921: Improved page resolution
 + S8155968: Update command line options
 + S8155973, CVE-2016-5542: Tighten jar checks (bsc#1005522)
 + S8157176: Improved classfile parsing
 + S8157739, CVE-2016-5554: Classloader Consistency Checking
 (bsc#1005523)
 + S8157749: Improve handling of DNS error replies
 + S8157753: Audio replay enhancement
 + S8157759: LCMS Transform Sampling Enhancement
 + S8157764: Better handling of interpolation plugins
 + S8158302: Handle contextual glyph substitutions
 + S8158993, CVE-2016-5568: Service Menu services (bsc#1005525)
 + S8159495: Fix index offsets
 + S8159503: Amend Annotation Actions
 + S8159511: Stack map validation
 + S8159515: Improve indy validation
 + S8159519, CVE-2016-5573: Reformat JDWP messages (bsc#1005526)
 + S8160090: Better signature handling in pack200
 + S8160094: Improve pack200 layout
 + S8160098: Clean up color profiles
 + S8160591, CVE-2016-5582: Improve internal array handling
 (bsc#1005527)
 + S8160838, CVE-2016-5597: Better HTTP service (bsc#1005528)
 + PR3207, RH1367357: lcms2: Out-of-bounds read in
 Type_MLU_Read()
 + CVE-2016-5556 (bsc#1005524)
 * Import of OpenJDK 7 u121 build 0
 + S6624200: Regression test fails:
 test/closed/javax/swing/JMenuItem/4654927/bug4654927.java
 + S6882559: new JEditorPane('text/plain','') fails for null
 context class loader
 + S7090158: Networking Libraries don't build with javac -Werror
 + S7125055: ContentHandler.getContent API changed in error
 + S7145960: sun/security/mscapi/ShortRSAKey1024.sh failing on
 windows
 + S7187051: ShortRSAKeynnn.sh tests should do cleanup before
 start test
 + S8000626: Implement dead key detection for KeyEvent on Linux
 + S8003890: corelibs test scripts should pass TESTVMOPTS
 + S8005629: javac warnings compiling
 java.awt.EventDispatchThread and sun.awt.X11.XIconWindow
 + S8010297: Missing isLoggable() checks in logging code
 + S8010782: clean up source files containing carriage return
 characters
 + S8014431: cleanup warnings indicated by the -Wunused-value
 compiler option on linux
 + S8015265: revise the fix for 8007037
 + S8016747: Replace deprecated PlatformLogger isLoggable(int)
 with isLoggable(Level)
 + S8020708: NLS mnemonics missing in SwingSet2/JInternalFrame
 demo
 + S8024756: method grouping tabs are not selectable
 + S8026741: jdk8 l10n resource file translation update 5
 + S8048147: Privilege tests with JAAS Subject.doAs
 + S8048357: PKCS basic tests
 + S8049171: Additional tests for jarsigner's warnings
 + S8059177: jdk8u40 l10n resource file translation update 1
 + S8075584: test for 8067364 depends on hardwired text advance
 + S8076486: [TESTBUG]
 javax/security/auth/Subject/doAs/NestedActions.java fails if
 extra VM options are given
 + S8077953: [TEST_BUG]
 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.121~36.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.121~36.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.121~36.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.121~36.2", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.121~36.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.121~36.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.121~36.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.121~36.2", rls:"SLES12.0SP2"))) {
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
