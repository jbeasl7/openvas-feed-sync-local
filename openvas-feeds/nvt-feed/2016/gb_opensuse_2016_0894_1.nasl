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
  script_oid("1.3.6.1.4.1.25623.1.0.851261");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-03-27 05:17:33 +0200 (Sun, 27 Mar 2016)");
  script_cve_id("CVE-2015-4477", "CVE-2015-7207", "CVE-2016-1952", "CVE-2016-1954",
                "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1960", "CVE-2016-1961",
                "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966",
                "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791",
                "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795",
                "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799",
                "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2016:0894-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaThunderbird was updated to 38.7.0 to fix the following issues:

  * Update to Thunderbird 38.7.0 (boo#969894)

  * MFSA 2015-81/CVE-2015-4477 (bmo#1179484) Use-after-free in MediaStream
  playback

  * MFSA 2015-136/CVE-2015-7207 (bmo#1185256) Same-origin policy violation
  using performance.getEntries and history navigation

  * MFSA 2016-16/CVE-2016-1952 Miscellaneous memory safety hazards

  * MFSA 2016-17/CVE-2016-1954 (bmo#1243178) Local file overwriting and
  potential privilege escalation through CSP reports

  * MFSA 2016-20/CVE-2016-1957 (bmo#1227052) Memory leak in libstagefright
  when deleting an array during MP4 processing

  * MFSA 2016-21/CVE-2016-1958 (bmo#1228754) Displayed page address can be
  overridden

  * MFSA 2016-23/CVE-2016-1960/ZDI-CAN-3545 (bmo#1246014) Use-after-free
  in HTML5 string parser

  * MFSA 2016-24/CVE-2016-1961/ZDI-CAN-3574 (bmo#1249377) Use-after-free
  in SetBody

  * MFSA 2016-25/CVE-2016-1962 (bmo#1240760) Use-after-free when using
  multiple WebRTC data channels

  * MFSA 2016-27/CVE-2016-1964 (bmo#1243335) Use-after-free during XML
  transformations

  * MFSA 2016-28/CVE-2016-1965 (bmo#1245264) Addressbar spoofing though
  history navigation and Location protocol property

  * MFSA 2016-31/CVE-2016-1966 (bmo#1246054) Memory corruption with
  malicious NPAPI plugin

  * MFSA 2016-34/CVE-2016-1974 (bmo#1228103) Out-of-bounds read in HTML
  parser following a failed allocation

  * MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
  CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
  CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
  CVE-2016-2800/CVE-2016-2801/CVE-2016-2802 Font vulnerabilities in the
  Graphite 2 library");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0894-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1")
{

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~38.7.0~70.80.1", rls:"openSUSE13.1"))) {
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
