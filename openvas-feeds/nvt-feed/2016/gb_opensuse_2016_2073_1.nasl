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
  script_oid("1.3.6.1.4.1.25623.1.0.851385");
  script_version("2021-10-14T14:01:34+0000");
  script_tag(name:"last_modification", value:"2021-10-14 14:01:34 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-08-16 05:43:14 +0200 (Tue, 16 Aug 2016)");
  script_cve_id("CVE-2014-9805", "CVE-2014-9807", "CVE-2014-9809", "CVE-2014-9815",
                "CVE-2014-9817", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9831",
                "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9837", "CVE-2014-9839",
                "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9853", "CVE-2015-8894",
                "CVE-2015-8896", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-5240",
                "CVE-2016-5241", "CVE-2016-5688");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for GraphicsMagick (openSUSE-SU-2016:2073-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for GraphicsMagick fixes the following issues:

  - CVE-2014-9805: SEGV due to a corrupted pnm file (boo#983752)

  - CVE-2016-5240: SVG converting issue resulting in DoS (endless loop)
  (boo#983309)

  - CVE-2016-5241: Arithmetic exception (div by 0) in SVG conversion
  (boo#983455)

  - CVE-2014-9846: Overflow in rle file (boo#983521)

  - CVE-2015-8894: Double free in TGA code (boo#983523)

  - CVE-2015-8896: Double free / integer truncation issue (boo#983533)

  - CVE-2014-9807: Double free in pdb coder (boo#983794)

  - CVE-2014-9809: SEGV due to corrupted xwd images (boo#983799)

  - CVE-2014-9819: Heap overflow in palm files (boo#984142)

  - CVE-2014-9835: Heap overflow in wpf file (boo#984145)

  - CVE-2014-9831: Issues handling of corrupted wpg file (boo#984375)

  - CVE-2014-9820: heap overflow in xpm files (boo#984150)

  - CVE-2014-9837: Additional PNM sanity checks (boo#984166)

  - CVE-2014-9815: Crash on corrupted wpg file (boo#984372)

  - CVE-2014-9839: Theoretical out of bound access in via color maps
  (boo#984379)

  - CVE-2014-9845: Crash due to corrupted dib file (boo#984394)

  - CVE-2014-9817: Heap buffer overflow in pdb file handling (boo#984400)

  - CVE-2014-9853: Memory leak in rle file handling (boo#984408)

  - CVE-2014-9834: Heap overflow in pict file (boo#984436)

  - CVE-2016-5688: Various invalid memory reads in ImageMagick WPG
  (boo#985442)

  - CVE-2016-2317: Multiple vulnerabilities when parsing and processing SVG
  files (boo#965853)

  - CVE-2016-2318: Multiple vulnerabilities when parsing and processing SVG
  files (boo#965853)");

  script_tag(name:"affected", value:"GraphicsMagick on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2073-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
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
  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-11", rpm:"libGraphicsMagick++-Q16-11~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-11-debuginfo", rpm:"libGraphicsMagick++-Q16-11-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1"))) {
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
