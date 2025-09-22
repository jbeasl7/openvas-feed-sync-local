# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852222");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-20184", "CVE-2018-20189");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-07 04:00:23 +0100 (Mon, 07 Jan 2019)");
  script_name("openSUSE: Security Advisory for GraphicsMagick (openSUSE-SU-2019:1-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the openSUSE-SU-2019:1-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for GraphicsMagick fixes the following issues:

  Security vulnerabilities fixed:

  - CVE-2018-20184: Fixed heap-based buffer overflow in the WriteTGAImage
  function of tga.c (bsc#1119822)

  - CVE-2018-20189: Fixed denial of service vulnerability in ReadDIBImage
  function of coders/dib.c (bsc#1119790)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1=1");

  script_tag(name:"affected", value:"GraphicsMagick on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12", rpm:"libGraphicsMagick++-Q16-12~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12-debuginfo", rpm:"libGraphicsMagick++-Q16-12-debuginfo~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.29~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
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
