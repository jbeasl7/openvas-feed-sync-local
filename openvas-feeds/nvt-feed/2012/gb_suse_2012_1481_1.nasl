# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850361");
  script_version("2021-05-28T06:21:45+0000");
  script_tag(name:"last_modification", value:"2021-05-28 06:21:45 +0000 (Fri, 28 May 2021)");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:18 +0530 (Thu, 13 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:1481-1");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2012:1481-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");

  script_tag(name:"affected", value:"opera on openSUSE 12.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"This Opera 12.10 security update fixes following security
  issues:

  - an issue that could cause Opera not to correctly check for
  certificate revocation

  - an issue where CORS requests could incorrectly retrieve
  contents of cross origin pages

  - an issue where data URIs could be used to facilitate
  Cross-Site Scripting

  - a high severity issue, as reported by Gareth Heyes.
  Details will be disclosed at a later date

  - an issue where specially crafted SVG images could allow
  execution of arbitrary code

  - a moderate severity issue, as reported by the Google
  Security Group. Details will be disclosed at a later date.

  Full changelog available at the referenced advisory.");

  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1210");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~12.10~26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera-gtk", rpm:"opera-gtk~12.10~26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera-kde4", rpm:"opera-kde4~12.10~26.1", rls:"openSUSE12.1"))) {
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
