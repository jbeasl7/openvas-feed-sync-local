# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1157.1");
  script_cve_id("CVE-2012-1956", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3974", "CVE-2012-3975", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3979", "CVE-2012-3980");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1157-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121157-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2012:1157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox was updated to 10.0.7ESR release, fixing a lot of bugs and security problems.

The following security issues have been addressed:

 *

 MFSA 2012-57: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 In general these flaws cannot be exploited through email in the Thunderbird and SeaMonkey products because scripting is disabled, but are potentially a risk in browser or browser-like contexts in those products.

 *

 CVE-2012-1971: Gary Kwong, Christian Holler, Jesse Ruderman, Steve Fink, Bob Clary, Andrew Sutherland, and Jason Smith reported memory safety problems and crashes that affect Firefox 14.

 *

 CVE-2012-1970: Gary Kwong, Christian Holler, Jesse Ruderman, John Schoenick, Vladimir Vukicevic and Daniel Holbert reported memory safety problems and crashes that affect Firefox ESR 10 and Firefox 14.

 *

 MFSA 2012-58: Security researcher Abhishek Arya
(Inferno) of Google Chrome Security Team discovered a series of use-after-free issues using the Address Sanitizer tool. Many of these issues are potentially exploitable,
allowing for remote code execution.

 o Heap-use-after-free in nsHTMLEditor::CollapseAdjacentTextNodes CVE-2012-1972 o Heap-use-after-free in nsObjectLoadingContent::LoadObject CVE-2012-1973 o Heap-use-after-free in gfxTextRun::CanBreakLineBefore CVE-2012-1974 o Heap-use-after-free in PresShell::CompleteMove CVE-2012-1975 o Heap-use-after-free in nsHTMLSelectElement::SubmitNamesValues CVE-2012-1976 o Heap-use-after-free in MediaStreamGraphThreadRunnable::Run() CVE-2012-3956 o Heap-buffer-overflow in nsBlockFrame::MarkLineDirty CVE-2012-3957 o Heap-use-after-free in nsHTMLEditRules::DeleteNonTableElements CVE-2012-3958 o Heap-use-after-free in nsRangeUpdater::SelAdjDeleteNode CVE-2012-3959 o Heap-use-after-free in mozSpellChecker::SetCurrentDictionary CVE-2012-3960 o Heap-use-after-free in RangeData::~RangeData CVE-2012-3961 o Bad iterator in text runs CVE-2012-3962 o use after free in js::gc::MapAllocToTraceKind CVE-2012-3963 o Heap-use-after-free READ 8 in gfxTextRun::GetUserData CVE-2012-3964
 *

 MFSA 2012-59 / CVE-2012-1956: Security researcher Mariusz Mlynski reported that it is possible to shadow the location object using Object.defineProperty. This could be used to confuse the current location to plugins, allowing for possible cross-site scripting (XSS) attacks.

 *

 MFSA 2012-60 / CVE-2012-3965: Security researcher Mariusz Mlynski reported that when a page opens a new tab,
a subsequent window can then be opened that can be navigated to about:newtab, a chrome privileged page. Once about:newtab is loaded, the special context can potentially be used to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0.7~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.6.7.80", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0.7~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.9.2~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.9.2~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-x86", rpm:"mozilla-nspr-x86~4.9.2~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.13.6~0.5.1", rls:"SLES11.0SP2"))) {
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
