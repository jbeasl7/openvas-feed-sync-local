# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1997.1");
  script_cve_id("CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-25 16:07:55 +0000 (Mon, 25 Jul 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1997-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1997-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161997-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989734");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002184.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2016:1997-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:

- Update to 2.6.7 - OpenJDK 7u111
 * Security fixes
 - S8079718, CVE-2016-3458: IIOP Input Stream Hooking
 (bsc#989732)
 - S8145446, CVE-2016-3485: Perfect pipe placement (Windows
 only) (bsc#989734)
 - S8147771: Construction of static protection domains under
 Javax custom policy
 - S8148872, CVE-2016-3500: Complete name checking (bsc#989730)
 - S8149962, CVE-2016-3508: Better delineation of XML processing
 (bsc#989731)
 - S8150752: Share Class Data
 - S8151925: Font reference improvements
 - S8152479, CVE-2016-3550: Coded byte streams (bsc#989733)
 - S8155981, CVE-2016-3606: Bolster bytecode verification
 (bsc#989722)
 - S8155985, CVE-2016-3598: Persistent Parameter Processing
 (bsc#989723)
 - S8158571, CVE-2016-3610: Additional method handle validation
 (bsc#989725)
 - CVE-2016-3511 (bsc#989727)
 - CVE-2016-3503 (bsc#989728)
 - CVE-2016-3498 (bsc#989729)
 * Import of OpenJDK 7 u111 build 0
 - S6953295: Move few sun.security.{util, x509, pkcs} classes
 used by keytool/jarsigner to another package
 - S7060849: Eliminate pack200 build warnings
 - S7064075: Security libraries don't build with
 javac -Xlint:all,-deprecation -Werror
 - S7069870: Parts of the JDK erroneously rely on generic array
 initializers with diamond
 - S7102686: Restructure timestamp code so that jars and modules
 can more easily share the same code
 - S7105780: Add SSLSocket client/SSLEngine server to templates
 directory
 - S7142339: PKCS7.java is needlessly creating SHA1PRNG
 SecureRandom instances when timestamping is not done
 - S7152582: PKCS11 tests should use the NSS libraries available
 in the OS
 - S7192202: Make sure keytool prints both unknown and
 unparseable extensions
 - S7194449: String resources for Key Tool and Policy Tool
 should be in their respective packages
 - S7196855: autotest.sh fails on ubuntu because libsoftokn.so
 not found
 - S7200682: TEST_BUG: keytool/autotest.sh still has problems
 with libsoftokn.so
 - S8002306: (se) Selector.open fails if invoked with thread
 interrupt status set [win]
 - S8009636: JARSigner including TimeStamp PolicyID
 (TSAPolicyID) as defined in RFC3161
 - S8019341: Update CookieHttpsClientTest to use the newer
 framework.
 - S8022228: Intermittent test failures in
 sun/security/ssl/javax/net/ssl/NewAPIs
 - S8022439: Fix lint warnings in sun.security.ec
 - S8022594: Potential deadlock in <clinit> of
 sun.nio.ch.Util/IOUtil
 - S8023546: sun/security/mscapi/ShortRSAKey1024.sh fails
 intermittently
 - S8036612: [parfait] JNI exception pending in
 jdk/src/windows/native/sun/security/mscapi/security.cpp
 - S8037557: test SessionCacheSizeTests.java timeout
 - S8038837: Add support to jarsigner for specifying timestamp
 hash algorithm
 - S8079410: Hotspot version to share the same update and build
 version from JDK
 - S8130735: javax.swing.TimerQueue: timer fires late when
 another timer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.111~33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.111~33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.111~33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.111~33.1", rls:"SLES12.0SP1"))) {
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
