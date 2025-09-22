# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851453");
  script_version("2021-10-14T14:01:34+0000");
  script_tag(name:"last_modification", value:"2021-10-14 14:01:34 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-12-14 05:54:12 +0100 (Wed, 14 Dec 2016)");
  script_cve_id("CVE-2016-5203", "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206",
                "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5210",
                "CVE-2016-5211", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214",
                "CVE-2016-5215", "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218",
                "CVE-2016-5219", "CVE-2016-5220", "CVE-2016-5221", "CVE-2016-5222",
                "CVE-2016-5223", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226",
                "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-07 21:15:00 +0000 (Fri, 07 Feb 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2016:3108-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Chromium 55.0.2883.75 fixes the following vulnerabilities:

  - CVE-2016-9651: Private property access in V8

  - CVE-2016-5208: Universal XSS in Blink

  - CVE-2016-5207: Universal XSS in Blink

  - CVE-2016-5206: Same-origin bypass in PDFium

  - CVE-2016-5205: Universal XSS in Blink

  - CVE-2016-5204: Universal XSS in Blink

  - CVE-2016-5209: Out of bounds write in Blink

  - CVE-2016-5203: Use after free in PDFium

  - CVE-2016-5210: Out of bounds write in PDFium

  - CVE-2016-5212: Local file disclosure in DevTools

  - CVE-2016-5211: Use after free in PDFium

  - CVE-2016-5213: Use after free in V8

  - CVE-2016-5214: File download protection bypass

  - CVE-2016-5216: Use after free in PDFium

  - CVE-2016-5215: Use after free in Webaudio

  - CVE-2016-5217: Use of unvalidated data in PDFium

  - CVE-2016-5218: Address spoofing in Omnibox

  - CVE-2016-5219: Use after free in V8

  - CVE-2016-5221: Integer overflow in ANGLE

  - CVE-2016-5220: Local file access in PDFium

  - CVE-2016-5222: Address spoofing in Omnibox

  - CVE-2016-9650: CSP Referrer disclosure

  - CVE-2016-5223: Integer overflow in PDFium

  - CVE-2016-5226: Limited XSS in Blink

  - CVE-2016-5225: CSP bypass in Blink

  - CVE-2016-5224: Same-origin bypass in SVG

  - CVE-2016-9652: Various fixes from internal audits, fuzzing and other
  initiatives

  The default bookmarks override was removed.

  The following packaging changes are included:

  - Switch to system libraries: harfbuzz, zlib, ffmpeg, where available.

  - Chromium now requires harfbuzz  = 1.3.0");

  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:3108-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~55.0.2883.75~148.1", rls:"openSUSE13.2"))) {
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
