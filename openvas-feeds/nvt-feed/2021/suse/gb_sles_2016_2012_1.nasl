# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2012.1");
  script_cve_id("CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3552", "CVE-2016-3587", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-25 16:07:55 +0000 (Mon, 25 Jul 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2012-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162012-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989734");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002198.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2016:2012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

- Upgrade to version jdk8u101 (icedtea 3.1.0)
- New in release 3.1.0 (2016-07-25):
 * Security fixes
 - S8079718, CVE-2016-3458: IIOP Input Stream Hooking
 (bsc#989732)
 - S8145446, CVE-2016-3485: Perfect pipe placement (Windows
 only) (bsc#989734)
 - S8146514: Enforce GCM limits
 - S8147771: Construction of static protection domains under
 Javax custom policy
 - S8148872, CVE-2016-3500: Complete name checking (bsc#989730)
 - S8149070: Enforce update ordering
 - S8149962, CVE-2016-3508: Better delineation of XML processing
 (bsc#989731)
 - S8150752: Share Class Data
 - S8151925: Font reference improvements
 - S8152479, CVE-2016-3550: Coded byte streams (bsc#989733)
 - S8153312: Constrain AppCDS behavior
 - S8154475, CVE-2016-3587: Clean up lookup visibility
 (bsc#989721)
 - S8155981, CVE-2016-3606: Bolster bytecode verification
 (bsc#989722)
 - S8155985, CVE-2016-3598: Persistent Parameter Processing
 (bsc#989723)
 - S8158571, CVE-2016-3610: Additional method handle validation
 (bsc#989725)
 - CVE-2016-3552 (bsc#989726)
 - CVE-2016-3511 (bsc#989727)
 - CVE-2016-3503 (bsc#989728)
 - CVE-2016-3498 (bsc#989729)
 * New features
 - S8145547, PR1061: [AWT/Swing] Conditional support for GTK 3
 on Linux
 - PR2821: Support building OpenJDK with --disable-headful
 - PR2931, G478960: Provide Infinality Support via fontconfig
 - PR3079: Provide option to build Shenandoah on x86_64
 * Import of OpenJDK 8 u92 build 14
 - S6869327: Add new C2 flag to keep safepoints in counted
 loops.
 - S8022865: [TESTBUG] Compressed Oops testing needs to be
 revised
 - S8029630: Thread id should be displayed as a hex number in
 error report
 - S8029726: On OS X some dtrace probe names are mismatched with
 Solaris
 - S8029727: On OS X dtrace probes
 Call<type>MethodA/Call<type>MethodV are not fired.
 - S8029728: On OS X dtrace probes SetStaticBooleanField are not
 fired
 - S8038184: XMLSignature throws StringIndexOutOfBoundsException
 if ID attribute value is empty String
 - S8038349: Signing XML with DSA throws Exception when key is
 larger than 1024 bits
 - S8041501: ImageIO reader is not capable of reading JPEGs
 without JFIF header
 - S8041900: [macosx] Java forces the use of discrete GPU
 - S8044363: Remove special build options for unpack200 executable
 - S8046471: Use OPENJDK_TARGET_CPU_ARCH instead of legacy value
 for hotspot ARCH
 - S8046611: Build errors with gcc on sparc/fastdebug
 - S8047763: Recognize sparc64 as a sparc platform
 - S8048232: Fix for 8046471 breaks PPC64 build
 - S8052396: Catch exceptions resulting from missing font cmap
 - S8058563: InstanceKlass::_dependencies list isn't cleared from
 empty nmethodBucket entries
 - S8061624: [TESTBUG] Some tests cannot be ran under compact
 profiles and therefore shall be excluded
 - S8062901: Iterators is spelled incorrectly in the Javadoc for
 Spliterator
 - S8064330: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.101~14.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.101~14.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.101~14.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.101~14.3", rls:"SLES12.0SP1"))) {
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
