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
  script_oid("1.3.6.1.4.1.25623.1.0.851372");
  script_version("2021-10-13T14:01:34+0000");
  script_tag(name:"last_modification", value:"2021-10-13 14:01:34 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-08-02 10:55:45 +0530 (Tue, 02 Aug 2016)");
  script_cve_id("CVE-2016-6232");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:31:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for karchive (openSUSE-SU-2016:1884-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'karchive'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for karchive fixes the following issues:

  - CVE-2016-6232: A remote attacker could have been able to overwrite
  arbitrary files when tricking the user into downloading KDE extras such
  as wallpapers or Plasma Applets (boo#989698)");

  script_tag(name:"affected", value:"karchive on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:1884-1");
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

  if(!isnull(res = isrpmvuln(pkg:"karchive-debugsource", rpm:"karchive-debugsource~5.11.0~27.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"karchive-devel", rpm:"karchive-devel~5.11.0~27.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5Archive5", rpm:"libKF5Archive5~5.11.0~27.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5Archive5-debuginfo", rpm:"libKF5Archive5-debuginfo~5.11.0~27.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"karchive-devel-32bit", rpm:"karchive-devel-32bit~5.11.0~27.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5Archive5-32bit", rpm:"libKF5Archive5-32bit~5.11.0~27.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libKF5Archive5-debuginfo-32bit", rpm:"libKF5Archive5-debuginfo-32bit~5.11.0~27.1", rls:"openSUSE13.2"))) {
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
