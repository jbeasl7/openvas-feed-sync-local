# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0896.1");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0896-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0896-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120896-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2012:0896-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox has been updated to the 10.0.6ESR security release fixing various bugs and several security issues,
some critical.

The following security issues have been fixed:

 *

 MFSA 2012-42: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 *

 CVE-2012-1948: Benoit Jacob, Jesse Ruderman,
Christian Holler, and Bill McCloskey reported memory safety problems and crashes that affect Firefox ESR 10 and Firefox 13.

 *

 MFSA 2012-43 / CVE-2012-1950: Security researcher Mario Gomes andresearch firm Code Audit Labs reported a mechanism to short-circuit page loads through drag and drop to the addressbar by canceling the page load. This causes the address of the previously site entered to be displayed in the addressbar instead of the currently loaded page.
This could lead to potential phishing attacks on users.

 *

 MFSA 2012-44 Google security researcher Abhishek Arya used the Address Sanitizer tool to uncover four issues: two use-after-free problems, one out of bounds read bug, and a bad cast. The first use-afte.r-free problem is caused when an array of nsSMILTimeValueSpec objects is destroyed but attempts are made to call into objects in this array later.
The second use-after-free problem is in nsDocument::AdoptNode when it adopts into an empty document and then adopts into another document, emptying the first one. The heap buffer overflow is in ElementAnimations when data is read off of end of an array and then pointers are dereferenced. The bad cast happens when nsTableFrame::InsertFrames is called with frames in aFrameList that are a mix of row group frames and column group frames. AppendFrames is not able to handle this mix.

 All four of these issues are potentially exploitable.

 o CVE-2012-1951: Heap-use-after-free in nsSMILTimeValueSpec::IsEventBased o CVE-2012-1954:
Heap-use-after-free in nsDocument::AdoptNode o CVE-2012-1953: Out of bounds read in ElementAnimations::EnsureStyleRuleFor o CVE-2012-1952: Bad cast in nsTableFrame::InsertFrames
 *

 MFSA 2012-45 / CVE-2012-1955: Security researcher Mariusz Mlynski reported an issue with spoofing of the location property. In this issue, calls to history.forward and history.back are used to navigate to a site while displaying the previous site in the addressbar but changing the baseURI to the newer site. This can be used for phishing by allowing the user input form or other data on the newer, attacking, site while appearing to be on the older, displayed site.

 *

 MFSA 2012-46 / CVE-2012-1966: Mozilla security researcher moz_bug_r_a4 reported a cross-site scripting
(XSS) attack through the context menu using a data: URL. In this issue, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0.6~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.6.7.70", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0.6~0.4.1", rls:"SLES11.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0.6~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.6.7.70", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0.6~0.4.1", rls:"SLES11.0SP2"))) {
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
