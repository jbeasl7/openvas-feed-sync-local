# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1624.1");
  script_cve_id("CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594", "CVE-2014-1595");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1624-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP1|SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1624-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141624-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2014:1624-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox has been updated to the 31.3ESR release fixing bugs and security issues.

 *

 MFSA 2014-83 / CVE-2014-1588 / CVE-2014-1587: Mozilla developers and community identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some
 of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some
 of these could be exploited to run arbitrary code.

 *

 MFSA 2014-85 / CVE-2014-1590: Security researcher Joe Vennix from Rapid7 reported that passing a JavaScript object to XMLHttpRequest that mimics an input stream will a crash. This crash is not exploitable and can only be used for denial of service attacks.

 *

 MFSA 2014-87 / CVE-2014-1592: Security researcher Berend-Jan Wever reported a use-after-free created by triggering the creation of a second root element while parsing HTML written to a document created with document.open(). This leads to a potentially exploitable crash.

 *

 MFSA 2014-88 / CVE-2014-1593: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team used the Address Sanitizer tool to discover a buffer overflow during the parsing of media content.
This leads to a potentially exploitable crash.

 *

 MFSA 2014-89 / CVE-2014-1594: Security researchers Byoungyoung Lee,
Chengyu Song, and Taesoo Kim at the Georgia Tech Information Security Center (GTISC) reported a bad casting from the BasicThebesLayer to BasicContainerLayer, resulting in undefined behavior. This behavior is potentially exploitable with some compilers but no clear mechanism to trigger it through web content was identified.

 *

 MFSA 2014-90 / CVE-2014-1595: Security researcher Kent Howard reported an Apple issue present in OS X 10.10 (Yosemite) where log files are created by the CoreGraphics framework of OS X in the /tmp local directory. These log files contain a record of all inputs into Mozilla programs during their operation. In versions of OS X from versions 10.6 through 10.9, the CoreGraphics had this logging ability but it was turned off by default. In OS X 10.10, this logging was turned on by default for some applications that use a custom memory allocator, such as jemalloc,
because of an initialization bug in the framework. This issue has been addressed in Mozilla products by explicitly turning off the framework's logging of input events. On vulnerable systems, this issue can result in private data such as usernames, passwords, and other inputed data being saved to a log file on the local system.

Security Issues:

 * CVE-2014-1587
 * CVE-2014-1588
 * CVE-2014-1589
 * CVE-2014-1590
 * CVE-2014-1591
 * CVE-2014-1592
 * CVE-2014-1593
 * CVE-2014-1594
 * CVE-2014-1595");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.3.0esr~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.3.0esr~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.3.0esr~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.3.0esr~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.3.0esr~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.3.0esr~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.3.0esr~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.3.0esr~0.8.1", rls:"SLES11.0SP3"))) {
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
