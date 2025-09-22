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
  script_oid("1.3.6.1.4.1.25623.1.0.851235");
  script_version("2021-09-20T14:01:48+0000");
  script_tag(name:"last_modification", value:"2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-03-13 06:17:05 +0100 (Sun, 13 Mar 2016)");
  script_cve_id("CVE-2016-2851");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libotr, libotr2 (openSUSE-SU-2016:0732-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libotr, libotr2'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libotr and libotr2 were updated to fix one security issue:

  - CVE-2016-2851: Integer overflow vulnerability allowed remote attackers
  to execute arbitrary code on 64 bit platforms (boo#969785)");

  script_tag(name:"affected", value:"libotr, libotr2 on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0732-1");
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

  if(!isnull(res = isrpmvuln(pkg:"libotr-debugsource", rpm:"libotr-debugsource~4.0.0~5.7.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr-devel", rpm:"libotr-devel~4.0.0~5.7.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr-tools", rpm:"libotr-tools~4.0.0~5.7.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr-tools-debuginfo", rpm:"libotr-tools-debuginfo~4.0.0~5.7.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr2", rpm:"libotr2~3.2.1~5.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr2-debuginfo", rpm:"libotr2-debuginfo~3.2.1~5.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr2-debugsource", rpm:"libotr2-debugsource~3.2.1~5.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr2-devel", rpm:"libotr2-devel~3.2.1~5.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr2-tools", rpm:"libotr2-tools~3.2.1~5.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr2-tools-debuginfo", rpm:"libotr2-tools-debuginfo~3.2.1~5.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr5", rpm:"libotr5~4.0.0~5.7.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libotr5-debuginfo", rpm:"libotr5-debuginfo~4.0.0~5.7.1", rls:"openSUSE13.1"))) {
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
