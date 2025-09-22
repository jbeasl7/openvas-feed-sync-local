# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0425.1");
  script_cve_id("CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0425-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0425-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120425-1/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2012:0425-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to 3.6.28 to fix various bugs and security issues.

The following security issues have been fixed:

 *

 MFSA 2012-19: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 In general these flaws cannot be exploited through email in the Thunderbird and SeaMonkey products because scripting is disabled, but are potentially a risk in browser or browser-like contexts in those products.
References

 Bob Clary reported two bugs that causes crashes that affected Firefox 3.6, Firefox ESR, and Firefox 10.
CVE-2012-0461

 Christian Holler, Jesse Ruderman, Nils, Michael Bebenita, Dindog, and David Anderson reported memory safety problems and crashes that affect Firefox ESR and Firefox 10. CVE-2012-0462

 Jeff Walden reported a memory safety problem in the array.join function. This bug was independently reported by Vincenzo Iozzo via TippingPoint's Zero Day Initiative Pwn2Own contest. CVE-2012-0464

 Masayuki Nakano reported a memory safety problem that affected Mobile Firefox 10. CVE-2012-0463

 *

 MFSA 2012-16 / CVE-2012-0458: Security researcher Mariusz Mlynski reported that an attacker able to convince a potential victim to set a new home page by dragging a link to the 'home' button can set that user's home page to a javascript: URL. Once this is done the attacker's page can cause repeated crashes of the browser, eventually getting the script URL loaded in the privileged about:sessionrestore context.

 *

 MFSA 2012-14 / CVE-2012-0457 / CVE-2012-0456:
Security researcher Atte Kettunen from OUSPG found two issues with Firefox's handling of SVG using the Address Sanitizer tool. The first issue, critically rated, is a use-after-free in SVG animation that could potentially lead to arbitrary code execution. The second issue is rated moderate and is an out of bounds read in SVG Filters. This could potentially incorporate data from the user's memory,
making it accessible to the page content.

 *

 MFSA 2012-13 / CVE-2012-0455: Firefox prevents the dropping of javascript: links onto a frame to prevent malicious sites from tricking users into performing a cross-site scripting (XSS) attacks on themselves. Security researcher Soroush Dalili reported a way to bypass this protection.

The full overview can be found on Mozillas security page at: [link moved to references]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.6.28~0.5.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.6.28~0.5.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.9.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.9.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-64bit", rpm:"mozilla-nspr-64bit~4.9.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.9.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-x86", rpm:"mozilla-nspr-x86~4.9.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.13.3~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.13.3~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-64bit", rpm:"mozilla-nss-64bit~3.13.3~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.13.3~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.13.3~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.13.3~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.28~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.28~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.28~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.28~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations", rpm:"mozilla-xulrunner192-translations~1.9.2.28~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-32bit", rpm:"mozilla-xulrunner192-translations-32bit~1.9.2.28~0.7.1", rls:"SLES10.0SP4"))) {
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
