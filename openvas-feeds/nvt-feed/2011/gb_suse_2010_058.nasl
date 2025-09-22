# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850151");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-01-04 09:11:34 +0100 (Tue, 04 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"SUSE-SA", value:"2010-058");
  script_cve_id("CVE-2010-3654", "CVE-2010-4091");
  script_name("SUSE: Security Advisory for acoread (SUSE-SA:2010:058)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'acoread'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.2)");

  script_tag(name:"impact", value:"remote code execution");

  script_tag(name:"affected", value:"acoread on openSUSE 11.1, openSUSE 11.2");

  script_tag(name:"insight", value:"Specially crafted PDF documents could crash acroread or lead to
  execution of arbitrary code. acroread was updated to version 9.4.1
  which addresses the issues.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

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

if(release == "openSUSE11.1") {
  if(!isnull(res = isrpmvuln(pkg:"acroread", rpm:"acroread~9.4.1~0.2.1", rls:"openSUSE11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"acroread-cmaps", rpm:"acroread-cmaps~9.4.1~0.2.1", rls:"openSUSE11.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE11.2") {
  if(!isnull(res = isrpmvuln(pkg:"acroread", rpm:"acroread~9.4.1~0.2.1", rls:"openSUSE11.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"acroread-cmaps", rpm:"acroread-cmaps~9.4.1~0.2.1", rls:"openSUSE11.2"))) {
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
