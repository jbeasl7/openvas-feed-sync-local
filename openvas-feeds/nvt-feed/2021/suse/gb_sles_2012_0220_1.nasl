# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0220.1");
  script_cve_id("CVE-2011-3659", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0220-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120220-1/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/firefox/10.0/releasenotes/");
  script_xref(name:"URL", value:"http://www.mozilla.org/de/firefox/features/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-06.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2012:0220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides Mozilla Firefox 10, which provides many fixes, security and feature enhancements.

For a detailed list, please have a look at

[link moved to references]

and

[link moved to references]

The following security issues have been fixed in this update:

 *

 Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances,
and we presume that with enough effort at least some of these could be exploited to run arbitrary code. (MFSA 2012-01, CVE-2012-0442
> , CVE-2012-0443
> )

 *

 Alex Dvorov reported that an attacker could replace a sub-frame in another domain's document by using the name attribute of the sub-frame as a form submission target.
This can potentially allow for phishing attacks against users and violates the HTML5 frame navigation policy. (MFSA 2012-03, CVE-2012-0445
> )

 *

 Security researcher regenrecht reported via TippingPoint's Zero Day Initiative that removed child nodes of nsDOMAttribute can be accessed under certain circumstances because of a premature notification of AttributeChildRemoved. This use-after-free of the child nodes could possibly allow for remote code execution.
(MFSA 2012-04, CVE-2011-3659
> )

 *

 Mozilla security researcher moz_bug_r_a4 reported that frame scripts bypass XPConnect security checks when calling untrusted objects. This allows for cross-site scripting (XSS) attacks through web pages and Firefox extensions. The fix enables the Script Security Manager
(SSM) to force security checks on all frame scripts. (MFSA 2012-05, CVE-2012-0446
> )

 *

 Mozilla developer Tim Abraldes reported that when encoding images as image/vnd.microsoft.icon the resulting data was always a fixed size, with uninitialized memory appended as padding beyond the size of the actual image.
This is the result of mImageBufferSize in the encoder being initialized with a value different than the size of the source image. There is the possibility of sensitive data from uninitialized memory being appended to a PNG image when converted fron an ICO format image. This sensitive data may then be disclosed in the resulting image. ((MFSA 2012-06)
[link moved to references]], [CVE-2012-0447
> )

 *

 Security researcher regenrecht reported via TippingPoint's Zero Day Initiative the possibility of memory corruption during the decoding of Ogg Vorbis files.
This can cause a crash during decoding and has the potential for remote code execution. (MFSA 2012-07, CVE-2012-0444
> )

 *

 Security researchers Nicolas Gregoire and Aki Helin independently reported that when processing a malformed embedded XSLT stylesheet, Firefox can crash due to a memory corruption. While there is no evidence that this is directly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Software Development Kit 11-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~10.0~0.3.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~7~0.6.7.7", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLES-for-VMware", rpm:"MozillaFirefox-branding-SLES-for-VMware~7~0.4.2.5", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~10.0~0.3.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-kde4-integration", rpm:"mozilla-kde4-integration~0.6.3~5.6.5", rls:"SLES11.0SP1"))) {
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
