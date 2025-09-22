# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131274");
  script_cve_id("CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204", "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210", "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7215", "CVE-2015-7216", "CVE-2015-7217", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220", "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223");
  script_tag(name:"creation_date", value:"2016-03-31 05:04:59 +0000 (Thu, 31 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2016-0124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0124");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0124.html");
  script_xref(name:"URL", value:"http://www.seamonkey-project.org/releases/seamonkey2.40/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17999");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-134/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-135/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-136/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-137/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-138/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-139/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-140/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-141/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-142/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-143/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-144/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-145/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-146/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-147/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-148/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-149/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2016-0124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allow remote
attackers to bypass the Same Origin Policy via data: and view-source:
URIs. (CVE-2015-7214)

The WebExtension APIs in Mozilla Firefox before 43.0 allow remote
attackers to gain privileges, and possibly obtain sensitive information or
conduct cross-site scripting (XSS) attacks, via a crafted web site.
(CVE-2015-7223)

Integer underflow in the Metadata::setData function in MetaData.cpp in
libstagefright in Mozilla Firefox before 43.0 and Firefox ESR 38.x before
38.5 allows remote attackers to execute arbitrary code or cause a denial
of service (incorrect memory allocation and application crash) via an MP4
video file with crafted covr metadata that triggers a buffer overflow.
(CVE-2015-7222)

Integer overflow in the MPEG4Extractor::readMetaData function in
MPEG4Extractor.cpp in libstagefright in Mozilla Firefox before 43.0 and
Firefox ESR 38.x before 38.5 on 64-bit platforms allows remote attackers
to execute arbitrary code via a crafted MP4 video file that triggers a
buffer overflow. (CVE-2015-7213)

Integer underflow in the RTPReceiverVideo::ParseRtpPacket function in
Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 might allow
remote attackers to obtain sensitive information, cause a denial of
service, or possibly have unspecified other impact by triggering a
crafted WebRTC RTP packet. (CVE-2015-7205)

Buffer overflow in the DirectWriteFontInfo::LoadFontFamilyData function in
gfx/thebes/gfxDWriteFontList.cpp in Mozilla Firefox before 43.0 might
allow remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted font-family name. (CVE-2015-7203)

Buffer overflow in the XDRBuffer::grow function in js/src/vm/Xdr.cpp in
Mozilla Firefox before 43.0 might allow remote attackers to cause a denial
of service or possibly have unspecified other impact via crafted
JavaScript code. (CVE-2015-7220)

Buffer overflow in the nsDeque::GrowCapacity function in
xpcom/glue/nsDeque.cpp in Mozilla Firefox before 43.0 might allow remote
attackers to cause a denial of service or possibly have unspecified other
impact by triggering a deque size change. (CVE-2015-7221)

The gdk-pixbuf configuration in Mozilla Firefox before 43.0 on Linux GNOME
platforms incorrectly enables the JasPer decoder, which allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via a crafted JPEG 2000 image. (CVE-2015-7216)

The gdk-pixbuf configuration in Mozilla Firefox before 43.0 on Linux GNOME
platforms incorrectly enables the TGA decoder, which allows remote
attackers to cause a denial of service (heap-based buffer overflow) via a
crafted Truevision TGA image. (CVE-2015-7217)

The HTTP/2 implementation in Mozilla Firefox before 43.0 allows remote
attackers to cause a denial of service (integer underflow, assertion
failure, and application exit) via a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.40~1.mga5", rls:"MAGEIA5"))) {
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
