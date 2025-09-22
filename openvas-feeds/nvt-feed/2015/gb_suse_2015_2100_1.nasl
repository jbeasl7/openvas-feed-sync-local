# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851135");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-12-29 17:30:29 +0530 (Tue, 29 Dec 2015)");
  script_cve_id("CVE-2015-8126");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libpng16 (openSUSE-SU-2015:2100-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng16'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libpng16 package was updated to fix the following security issues:

  - CVE-2015-8126: Fixed a buffer overflow vulnerabilities in
  png_get_PLTE/png_set_PLTE functions (bsc#954980).");

  script_tag(name:"affected", value:"libpng16 on openSUSE 13.2, openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:2100-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE13\.2|openSUSE13\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2") {
  if(!isnull(res = isrpmvuln(pkg:"libpng16-16", rpm:"libpng16-16~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-debuginfo", rpm:"libpng16-16-debuginfo~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel", rpm:"libpng16-compat-devel~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-debugsource", rpm:"libpng16-debugsource~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel", rpm:"libpng16-devel~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-tools", rpm:"libpng16-tools~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-tools-debuginfo", rpm:"libpng16-tools-debuginfo~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-32bit", rpm:"libpng16-16-32bit~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-debuginfo-32bit", rpm:"libpng16-16-debuginfo-32bit~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel-32bit", rpm:"libpng16-compat-devel-32bit~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel-32bit", rpm:"libpng16-devel-32bit~1.6.13~2.7.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"libpng16-16", rpm:"libpng16-16~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-debuginfo", rpm:"libpng16-16-debuginfo~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel", rpm:"libpng16-compat-devel~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-debugsource", rpm:"libpng16-debugsource~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel", rpm:"libpng16-devel~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-tools", rpm:"libpng16-tools~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-tools-debuginfo", rpm:"libpng16-tools-debuginfo~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-32bit", rpm:"libpng16-16-32bit~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-debuginfo-32bit", rpm:"libpng16-16-debuginfo-32bit~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel-32bit", rpm:"libpng16-compat-devel-32bit~1.6.6~19.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel-32bit", rpm:"libpng16-devel-32bit~1.6.6~19.1", rls:"openSUSE13.1"))) {
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
