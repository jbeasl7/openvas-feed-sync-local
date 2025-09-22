# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131284");
  script_cve_id("CVE-2016-1622", "CVE-2016-1623", "CVE-2016-1624", "CVE-2016-1625", "CVE-2016-1626", "CVE-2016-1627", "CVE-2016-1628", "CVE-2016-1629", "CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641", "CVE-2016-1642", "CVE-2016-1643", "CVE-2016-1644", "CVE-2016-1645", "CVE-2016-1646", "CVE-2016-1647", "CVE-2016-1648", "CVE-2016-1649", "CVE-2016-1650");
  script_tag(name:"creation_date", value:"2016-04-04 04:30:03 +0000 (Mon, 04 Apr 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 18:59:47 +0000 (Mon, 07 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0127");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0127.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/02/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/02/stable-channel-update_18.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/02/stable-channel-update_9.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/03/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/03/stable-channel-update_24.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/03/stable-channel-update_8.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17729");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser-stable 49.0.2623.108 fixes security issues:

Multiple security issues were found in upstream chromium 49.0.2623.87: an
out-of-bounds read problem in V8 (CVE-2016-1646), use-after-free bugs in
Navigation (CVE-2016-1647) and Extensions (CVE-2016-1648), a buffer
overflow in libANGLE (CVE-2016-1649), various security issues found in
internal audits, fuzzing, and other initiatives (CVE-2016-1650), multiple
vulnerabilities in V8 were fixed in 4.9.385.33.

The ImageInputType::ensurePrimaryContent function in
WebKit/Source/core/html/forms/ImageInputType.cpp in Blink, as used in
Google Chrome before 49.0.2623.87, does not properly maintain the user
agent shadow DOM, which allows remote attackers to cause a denial of
service or possibly have unspecified other impact via vectors that
leverage 'type confusion.' (CVE-2016-1643)

WebKit/Source/core/layout/LayoutObject.cpp in Blink, as used in Google
Chrome before 49.0.2623.87, does not properly restrict relayout
scheduling, which allows remote attackers to cause a denial of service
(use-after-free) or possibly have unspecified other impact via a crafted
HTML document. (CVE-2016-1644)

Multiple integer signedness errors in the opj_j2k_update_image_data
function in j2k.c in OpenJPEG, as used in PDFium in Google Chrome before
49.0.2623.87, allow remote attackers to cause a denial of service
(incorrect cast and out-of-bounds write) or possibly have unspecified
other impact via crafted JPEG 2000 data. (CVE-2016-1645)

The ContainerNode::parserRemoveChild function in
WebKit/Source/core/dom/ContainerNode.cpp in Blink, as used in Google
Chrome before 49.0.2623.75, mishandles widget updates, which makes it
easier for remote attackers to bypass the Same Origin Policy via a
crafted web site. (CVE-2016-1630)

The PPB_Flash_MessageLoop_Impl::InternalRun function in
content/renderer/pepper/ppb_flash_message_loop_impl.cc in the Pepper
plugin in Google Chrome before 49.0.2623.75 mishandles nested message
loops, which allows remote attackers to bypass the Same Origin Policy via
a crafted web site. (CVE-2016-1631)

The Extensions subsystem in Google Chrome before 49.0.2623.75 does not
properly maintain own properties, which allows remote attackers to bypass
intended access restrictions via crafted JavaScript code that triggers an
incorrect cast, related to extensions/renderer/v8_helpers.h and
gin/converter.h. (CVE-2016-1632)

Use-after-free vulnerability in Blink, as used in Google Chrome before
49.0.2623.75, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.
(CVE-2016-1633)

Use-after-free vulnerability in the StyleResolver::appendCSSStyleSheet
function in WebKit/Source/core/css/resolver/StyleResolver.cpp in Blink, as
used in Google Chrome before 49.0.2623.75, allows remote attackers to
cause a denial of service or possibly have unspecified other impact via a
crafted web ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~49.0.2623.108~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~49.0.2623.108~1.1.mga5", rls:"MAGEIA5"))) {
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
