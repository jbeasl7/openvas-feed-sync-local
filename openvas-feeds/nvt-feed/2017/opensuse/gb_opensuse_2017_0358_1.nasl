# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851484");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-02-03 12:11:19 +0530 (Fri, 03 Feb 2017)");
  script_cve_id("CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376",
                "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380",
                "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384",
                "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388",
                "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5392",
                "CVE-2017-5393", "CVE-2017-5394", "CVE-2017-5395", "CVE-2017-5396");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:34:00 +0000 (Thu, 02 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2017:0358-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to version 51.0.1 fixes security issues and
  bugs.

  These security issues were fixed:

  * CVE-2017-5375: Excessive JIT code allocation allows bypass of ASLR and
  DEP (bmo#1325200, boo#1021814)

  * CVE-2017-5376: Use-after-free in XSL (bmo#1311687, boo#1021817)
  CVE-2017-5377: Memory corruption with transforms to create gradients in
  Skia (bmo#1306883, boo#1021826)

  * CVE-2017-5378: Pointer and frame data leakage of Javascript objects
  (bmo#1312001, bmo#1330769, boo#1021818)

  * CVE-2017-5379: Use-after-free in Web Animations (bmo#1309198, boo#1021827)

  * CVE-2017-5380: Potential use-after-free during DOM manipulations
  (bmo#1322107, boo#1021819)

  * CVE-2017-5390: Insecure communication methods in Developer Tools JSON
  viewer (bmo#1297361, boo#1021820)

  * CVE-2017-5389: WebExtensions can install additional add-ons via modified
  host requests (bmo#1308688, boo#1021828)

  * CVE-2017-5396: Use-after-free with Media Decoder (bmo#1329403,
  boo#1021821)

  * CVE-2017-5381: Certificate Viewer exporting can be used to navigate and
  save to arbitrary filesystem locations (bmo#1017616, boo#1021830)

  * CVE-2017-5382: Feed preview can expose privileged content errors and
  exceptions (bmo#1295322, boo#1021831)

  * CVE-2017-5383: Location bar spoofing with unicode characters
  (bmo#1323338, bmo#1324716, boo#1021822)

  * CVE-2017-5384: Information disclosure via Proxy Auto-Config (PAC)
  (bmo#1255474, boo#1021832)

  * CVE-2017-5385: Data sent in multipart channels ignores referrer-policy
  response headers (bmo#1295945, boo#1021833)

  * CVE-2017-5386: WebExtensions can use data: protocol to affect other
  extensions (bmo#1319070, boo#1021823)

  * CVE-2017-5391: Content about: pages can load privileged about: pages
  (bmo#1309310, boo#1021835)

  * CVE-2017-5393: Remove addons.mozilla.org CDN from whitelist for
  mozAddonManager (bmo#1309282, boo#1021837)

  * CVE-2017-5387: Disclosure of local file existence through TRACK tag
  error messages (bmo#1295023, boo#1021839)

  * CVE-2017-5388: WebRTC can be used to generate a large amount of UDP
  traffic for DDOS attacks (bmo#1281482, boo#1021840)

  * CVE-2017-5374: Memory safety bugs (boo#1021841)

  * CVE-2017-5373: Memory safety bugs (boo#1021824)

  These non-security issues in MozillaFirefox were fixed:

  * Added support for FLAC (Free Lossless Audio Codec) playback

  * Added support for WebGL 2

  * Added Georgian (ka) and Kabyle (kab) locales

  * Support saving passwords for forms without 'submit' events

  * Improved video performance for users without GPU acceleration

  * Zoom indicator is shown ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"MozillaFirefox on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:0358-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~51.0.1~50.2", rls:"openSUSELeap42.1"))) {
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
