# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850456");
  script_version("2022-07-05T11:37:01+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:01 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:31 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-2492");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2013:0504-1");
  script_name("openSUSE: Security Advisory for firebird (openSUSE-SU-2013:0504-1)");

  script_tag(name:"affected", value:"firebird on openSUSE 11.4");

  script_tag(name:"insight", value:"This update fixes a bug which allows an unauthenticated
  remote attacker to cause a stack overflow in server code,
  resulting in either server crash or even code execution as
  the user running firebird.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firebird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-classic-debuginfo", rpm:"firebird-classic-debuginfo~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-debuginfo", rpm:"firebird-debuginfo~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-debugsource", rpm:"firebird-debugsource~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-devel-debuginfo", rpm:"firebird-devel-debuginfo~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-doc", rpm:"firebird-doc~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-filesystem", rpm:"firebird-filesystem~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-superserver-debuginfo", rpm:"firebird-superserver-debuginfo~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfbclient2-debuginfo", rpm:"libfbclient2-debuginfo~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfbembed2", rpm:"libfbembed2~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfbembed2-debuginfo", rpm:"libfbembed2-debuginfo~2.1.3.18185.0~16.1", rls:"openSUSE11.4"))) {
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
