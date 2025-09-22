# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0306.1");
  script_cve_id("CVE-2012-5829", "CVE-2013-0743", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0306-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130306-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2013:0306-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is updated to the 10.0.12ESR version.

This is a roll-up update for LTSS.

It fixes a lot of security issues and bugs. 10.0.12ESR fixes specifically:

 *

 MFSA 2013-01: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 Christoph Diehl, Christian Holler, Mats Palmgren, and Chiaki Ishikawa reported memory safety problems and crashes that affect Firefox ESR 10, Firefox ESR 17, and Firefox 17.
(CVE-2013-0769)

 Bill Gianopoulos, Benoit Jacob, Christoph Diehl,
Christian Holler, Gary Kwong, Robert O'Callahan, and Scoobidiver reported memory safety problems and crashes that affect Firefox ESR 17 and Firefox 17. (CVE-2013-0749)

 Jesse Ruderman, Christian Holler, Julian Seward, and Scoobidiver reported memory safety problems and crashes that affect Firefox 17. (CVE-2013-0770)

 *

 MFSA 2013-02: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team discovered a series critically rated of use-after-free, out of bounds read, and buffer overflow issues using the Address Sanitizer tool in shipped software. These issues are potentially exploitable, allowing for remote code execution. We would also like to thank Abhishek for reporting three additional user-after-free and out of bounds read flaws introduced during Firefox development that were fixed before general release.

 The following issue has been fixed in Firefox 18:

 o Global-buffer-overflow in CharDistributionAnalysis::HandleOneChar (CVE-2013-0760)

 The following issues has been fixed in Firefox 18,
ESR 17.0.1, and ESR 10.0.12:

 o Heap-use-after-free in imgRequest::OnStopFrame
(CVE-2013-0762) o Heap-use-after-free in ~nsHTMLEditRules
(CVE-2013-0766) o Out of bounds read in nsSVGPathElement::GetPathLengthScale (CVE-2013-0763) o Heap-buffer-overflow in gfxTextRun::ShrinkToLigatureBoundaries (CVE-2013-0771)

 The following issue has been fixed in Firefox 18 and in the earlier ESR 10.0.11 release:

 o Heap-buffer-overflow in nsWindow::OnExposeEvent
(CVE-2012-5829)
 *

 MFSA 2013-03: Security researcher miaubiz used the Address Sanitizer tool to discover a buffer overflow in Canvas when specific bad height and width values were given through HTML. This could lead to a potentially exploitable crash. (CVE-2013-0768)

 Miaubiz also found a potentially exploitable crash when 2D and 3D content was mixed which was introduced during Firefox development and fixed before general release.

 *

 MFSA 2013-04: Security researcher Masato Kinugawa found a flaw in which the displayed URL values within the addressbar can be spoofed by a page during loading. This allows for phishing attacks where a malicious page can spoof the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0.12~0.6.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.8.46", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0.12~0.6.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-cairo", rpm:"firefox3-cairo~1.2.4~0.8.5", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-cairo-32bit", rpm:"firefox3-cairo-32bit~1.2.4~0.8.5", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-gtk2", rpm:"firefox3-gtk2~2.10.6~0.12.21", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-gtk2-32bit", rpm:"firefox3-gtk2-32bit~2.10.6~0.12.21", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-pango", rpm:"firefox3-pango~1.14.5~0.12.178", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox3-pango-32bit", rpm:"firefox3-pango-32bit~1.14.5~0.12.178", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.9.4~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.9.4~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.9.4~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.14.1~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.14.1~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.14.1~0.6.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.14.1~0.6.1", rls:"SLES10.0SP3"))) {
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
