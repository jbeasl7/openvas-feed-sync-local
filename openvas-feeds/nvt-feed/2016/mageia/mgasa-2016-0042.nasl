# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131200");
  script_cve_id("CVE-2016-1612", "CVE-2016-1613", "CVE-2016-1614", "CVE-2016-1615", "CVE-2016-1616", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1619", "CVE-2016-1620");
  script_tag(name:"creation_date", value:"2016-02-02 05:44:17 +0000 (Tue, 02 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-26 15:42:35 +0000 (Tue, 26 Jan 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0042");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0042.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/01/stable-channel-update_20.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/01/stable-channel-update_27.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17567");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The LoadIC::UpdateCaches function in ic/ic.cc in Google V8, as used in
Google Chrome before 48.0.2564.82, does not ensure receiver compatibility
before performing a cast of an unspecified variable, which allows remote
attackers to cause a denial of service or possibly have unknown other
impact via crafted JavaScript code. (CVE-2016-1612)

Multiple use-after-free vulnerabilities in the formfiller implementation
in PDFium, as used in Google Chrome before 48.0.2564.82, allow remote
attackers to cause a denial of service or possibly have unspecified other
impact via a crafted PDF document, related to improper tracking of the
destruction of (1) IPWL_FocusHandler and (2) IPWL_Provider objects.
(CVE-2016-1613)

The UnacceleratedImageBufferSurface class in
WebKit/Source/platform/graphics/UnacceleratedImageBufferSurface.cpp in
Blink, as used in Google Chrome before 48.0.2564.82, mishandles the
initialization mode, which allows remote attackers to obtain sensitive
information from process memory via a crafted web site. (CVE-2016-1614)

The Omnibox implementation in Google Chrome before 48.0.2564.82 allows
remote attackers to spoof a document's origin via unspecified vectors.
(CVE-2016-1615)

The CustomButton::AcceleratorPressed function in
ui/views/controls/button/custom_button.cc in Google Chrome before
48.0.2564.82 allows remote attackers to spoof URLs via vectors involving
an unfocused custom button. (CVE-2016-1616)

The CSPSource::schemeMatches function in
WebKit/Source/core/frame/csp/CSPSource.cpp in the Content Security Policy
(CSP) implementation in Blink, as used in Google Chrome before
48.0.2564.82, does not apply http policies to https URLs and does not
apply ws policies to wss URLs, which makes it easier for remote attackers
to determine whether a specific HSTS web site has been visited by reading
a CSP report. (CVE-2016-1617)

Blink, as used in Google Chrome before 48.0.2564.82, does not ensure that
a proper cryptographicallyRandomValues random number generator is used,
which makes it easier for remote attackers to defeat cryptographic
protection mechanisms via unspecified vectors. (CVE-2016-1618)

Multiple integer overflows in the (1) sycc422_to_rgb and (2)
sycc444_to_rgb functions in fxcodec/codec/fx_codec_jpx_opj.cpp in PDFium,
as used in Google Chrome before 48.0.2564.82, allow remote attackers to
cause a denial of service (out-of-bounds read) or possibly have
unspecified other impact via a crafted PDF document. (CVE-2016-1619)

Multiple unspecified vulnerabilities in Google Chrome before 48.0.2564.82
allow attackers to cause a denial of service or possibly have other impact
via unknown vectors. (CVE-2016-1620)

The included V8 version 4.8.271.17 fixes multiple vulnerabilities.");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~48.0.2564.97~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~48.0.2564.97~1.mga5", rls:"MAGEIA5"))) {
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
