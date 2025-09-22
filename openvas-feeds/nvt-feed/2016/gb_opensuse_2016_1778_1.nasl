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
  script_oid("1.3.6.1.4.1.25623.1.0.851366");
  script_version("2021-10-11T13:01:25+0000");
  script_tag(name:"last_modification", value:"2021-10-11 13:01:25 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-07-11 05:26:25 +0200 (Mon, 11 Jul 2016)");
  script_cve_id("CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955",
                "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1960", "CVE-2016-1961",
                "CVE-2016-1964", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790",
                "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794",
                "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798",
                "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802",
                "CVE-2016-2806", "CVE-2016-2807", "CVE-2016-2815", "CVE-2016-2818");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2016:1778-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains Mozilla Thunderbird 45.2. (boo#983549)

  It fixes security issues mostly affecting the e-mail program when used in
  a browser context, such as viewing a web page or HTMl formatted e-mail.

  The following vulnerabilities were fixed:

  - CVE-2016-2818, CVE-2016-2815: Memory safety bugs (boo#983549,
  MFSA2016-49)

  Contains the following security fixes from the 45.1 release: (boo#977333)

  - CVE-2016-2806, CVE-2016-2807: Miscellaneous memory safety hazards
  (boo#977375, boo#977376, MFSA 2016-39)

  Contains the following security fixes from the 45.0 release: (boo#969894)

  - CVE-2016-1952, CVE-2016-1953: Miscellaneous memory safety hazards (MFSA
  2016-16)

  - CVE-2016-1954: Local file overwriting and potential privilege escalation
  through CSP reports (MFSA 2016-17)

  - CVE-2016-1955: CSP reports fail to strip location information for
  embedded iframe pages (MFSA 2016-18)

  - CVE-2016-1956: Linux video memory DOS with Intel drivers (MFSA 2016-19)

  - CVE-2016-1957: Memory leak in libstagefright when deleting an array
  during MP4 processing (MFSA 2016-20)

  - CVE-2016-1960: Use-after-free in HTML5 string parser (MFSA 2016-23)

  - CVE-2016-1961: Use-after-free in SetBody (MFSA 2016-24)

  - CVE-2016-1964: Use-after-free during XML transformations (MFSA 2016-27)

  - CVE-2016-1974: Out-of-bounds read in HTML parser following a failed
  allocation (MFSA 2016-34)

  The graphite font shaping library was disabled, addressing the following
  font vulnerabilities:

  - MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
  CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
  CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
  CVE-2016-2800/CVE-2016-2801/CVE-2016-2802

  The following tracked packaging changes are included:

  - fix build issues with gcc/binutils combination used in Leap 42.2
  (boo#984637)

  - gcc6 fixes (boo#986162)

  - running on 48bit va aarch64 (boo#984126)");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:1778-1");
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~45.2~43.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~45.2~43.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~45.2~43.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~45.2~43.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~45.2~43.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~45.2~43.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~45.2~43.1", rls:"openSUSE13.2"))) {
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
