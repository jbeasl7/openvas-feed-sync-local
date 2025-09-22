# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1152.1");
  script_cve_id("CVE-2012-1942", "CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0798", "CVE-2013-0799", "CVE-2013-0800", "CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1672", "CVE-2013-1673", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1697");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:25:57 +0000 (Tue, 09 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1152-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131152-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2013:1152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox has been updated to the 17.0.7 ESR version,
which fixes bugs and security fixes.

 *

 MFSA 2013-49: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 Gary Kwong, Jesse Ruderman, and Andrew McCreight reported memory safety problems and crashes that affect Firefox ESR 17, and Firefox 21. (CVE-2013-1682)

 *

 MFSA 2013-50: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team used the Address Sanitizer tool to discover a series of use-after-free problems rated critical as security issues in shipped software. Some of these issues are potentially exploitable, allowing for remote code execution. We would also like to thank Abhishek for reporting additional use-after-free and buffer overflow flaws in code introduced during Firefox development. These were fixed before general release.

 o Heap-use-after-free in mozilla::dom::HTMLMediaElement::LookupMediaElementURITable
(CVE-2013-1684) o Heap-use-after-free in nsIDocument::GetRootElement (CVE-2013-1685) o Heap-use-after-free in mozilla::ResetDir (CVE-2013-1686)
 *

 MFSA 2013-51 / CVE-2013-1687: Security researcher Mariusz Mlynski reported that it is possible to compile a user-defined function in the XBL scope of a specific element and then trigger an event within this scope to run code. In some circumstances, when this code is run, it can access content protected by System Only Wrappers (SOW) and chrome-privileged pages. This could potentially lead to arbitrary code execution. Additionally, Chrome Object Wrappers (COW) can be bypassed by web content to access privileged methods, leading to a cross-site scripting (XSS)
attack from privileged pages.

 *

 MFSA 2013-53 / CVE-2013-1690: Security researcher Nils reported that specially crafted web content using the onreadystatechange event and reloading of pages could sometimes cause a crash when unmapped memory is executed.
This crash is potentially exploitable.

 *

 MFSA 2013-54 / CVE-2013-1692: Security researcher Johnathan Kuskos reported that Firefox is sending data in the body of XMLHttpRequest (XHR) HEAD requests, which goes agains the XHR specification. This can potentially be used for Cross-Site Request Forgery (CSRF) attacks against sites which do not distinguish between HEAD and POST requests.

 *

 MFSA 2013-55 / CVE-2013-1693: Security researcher Paul Stone of Context Information Security discovered that timing differences in the processing of SVG format images with filters could allow for pixel values to be read. This could potentially allow for text values to be read across domains, leading to information disclosure.

 *

 MFSA 2013-59 / ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.7esr~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.7esr~0.8.1", rls:"SLES11.0SP3"))) {
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
