# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131304");
  script_cve_id("CVE-2016-1651", "CVE-2016-1652", "CVE-2016-1653", "CVE-2016-1654", "CVE-2016-1655", "CVE-2016-1657", "CVE-2016-1658", "CVE-2016-1659");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:07 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 21:02:16 +0000 (Mon, 18 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0143)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0143");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0143.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/04/stable-channel-update_13.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18205");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0143 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser-stable 50.0.2661.75 fixes security issues:

Cross-site scripting (XSS) vulnerability in the ModuleSystem::RequireForJsInner
function in extensions/renderer/module_system.cc in the Extensions subsystem in
Google Chrome before 50.0.2661.75 allows remote attackers to inject arbitrary
web script or HTML via a crafted web site, aka 'Universal XSS (UXSS).'
(CVE-2016-1652)

The LoadBuffer implementation in Google V8, as used in Google Chrome before
50.0.2661.75, mishandles data types, which allows remote attackers to cause a
denial of service or possibly have unspecified other impact via crafted
JavaScript code that triggers an out-of-bounds write operation, related to
compiler/pipeline.cc and compiler/simplified-lowering.cc. (CVE-2016-1653)

fxcodec/codec/fx_codec_jpx_opj.cpp in PDFium, as used in Google Chrome before
50.0.2661.75, does not properly implement the sycc420_to_rgb and sycc422_to_rgb
functions, which allows remote attackers to obtain sensitive information from
process memory or cause a denial of service (out-of-bounds read) via crafted
JPEG 2000 data in a PDF document. (CVE-2016-1651)

The media subsystem in Google Chrome before 50.0.2661.75 does not initialize an
unspecified data structure, which allows remote attackers to cause a denial of
service (invalid read operation) via unknown vectors. (CVE-2016-1654)

Google Chrome before 50.0.2661.75 does not properly consider that frame removal
may occur during callback execution, which allows remote attackers to cause a
denial of service (use-after-free) or possibly have unspecified other impact via
a crafted extension. (CVE-2016-1655)

The WebContentsImpl::FocusLocationBarByDefault function in
content/browser/web_contents/web_contents_impl.cc in Google Chrome before
50.0.2661.75 mishandles focus for certain about:blank pages, which allows remote
attackers to spoof the address bar via a crafted URL. (CVE-2016-1657)

The Extensions subsystem in Google Chrome before 50.0.2661.75 incorrectly relies
on GetOrigin method calls for origin comparisons, which allows remote attackers
to bypass the Same Origin Policy and obtain sensitive information via a crafted
extension. (CVE-2016-1658)

Multiple unspecified vulnerabilities in Google Chrome before 50.0.2661.75 allow
attackers to cause a denial of service or possibly have other impact via unknown
vectors. (CVE-2016-1659)");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~50.0.2661.75~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~50.0.2661.75~1.mga5", rls:"MAGEIA5"))) {
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
