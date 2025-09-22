# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0048.1");
  script_cve_id("CVE-2012-5829", "CVE-2013-0743", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0048-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130048-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2013:0048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to the 10.0.12ESR release.

 *

 MFSA 2013-01: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 o Christoph Diehl, Christian Holler, Mats Palmgren, and Chiaki Ishikawa reported memory safety problems and crashes that affect Firefox ESR 10, Firefox ESR 17, and Firefox 17. ( CVE-2013-0769
> ) o Bill Gianopoulos, Benoit Jacob, Christoph Diehl,
Christian Holler, Gary Kwong, Robert O'Callahan, and Scoobidiver reported memory safety problems and crashes that affect Firefox ESR 17 and Firefox 17. (CVE-2013-0749
> ) o Jesse Ruderman, Christian Holler, Julian Seward, and Scoobidiver reported memory safety problems and crashes that affect Firefox 17. (CVE-2013-0770
> )
 *

 MFSA 2013-02: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team discovered a series critically rated of use-after-free, out of bounds read, and buffer overflow issues using the Address Sanitizer tool in shipped software. These issues are potentially exploitable, allowing for remote code execution. We would also like to thank Abhishek for reporting three additional user-after-free and out of bounds read flaws introduced during Firefox development that were fixed before general release.

 The following issue was fixed in Firefox 18:

 o Global-buffer-overflow in CharDistributionAnalysis::HandleOneChar (CVE-2013-0760
> )

 The following issues were fixed in Firefox 18, ESR 17.0.1, and ESR 10.0.12:

 o Heap-use-after-free in imgRequest::OnStopFrame
(CVE-2013-0762
> ) o Heap-use-after-free in ~nsHTMLEditRules
(CVE-2013-0766
> ) o Out of bounds read in nsSVGPathElement::GetPathLengthScale ( CVE-2013-0767
> )

 The following issues were fixed in Firefox 18 and ESR 17.0.1:

 o Heap-use-after-free in mozilla::TrackUnionStream::EndTrack ( CVE-2013-0761
> ) o Heap-use-after-free in Mesa, triggerable by resizing a WebGL canvas (CVE-2013-0763
> ) o Heap-buffer-overflow in gfxTextRun::ShrinkToLigatureBoundaries (CVE-2013-0771
> )

 The following issue was fixed in Firefox 18 and in the earlier ESR 10.0.11 release:

 o Heap-buffer-overflow in nsWindow::OnExposeEvent
(CVE-2012-5829
> )
 *

 MFSA 2013-03: Security researcher miaubiz used the Address Sanitizer tool to discover a buffer overflow in Canvas when specific bad height and width values were given through HTML. This could lead to a potentially exploitable crash. (CVE-2013-0768
> )

 Miaubiz also found a potentially exploitable crash when 2D and 3D content was mixed which was introduced during Firefox development and fixed before general release.

 *

 MFSA 2013-04: Security researcher Masato Kinugawa found a flaw in which the displayed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0.12~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0.12~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.9.4~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.9.4~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-x86", rpm:"mozilla-nspr-x86~4.9.4~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.14.1~0.3.1", rls:"SLES11.0SP2"))) {
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
