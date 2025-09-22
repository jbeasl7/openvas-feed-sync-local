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
  script_oid("1.3.6.1.4.1.25623.1.0.851214");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-03-01 11:08:54 +0530 (Tue, 01 Mar 2016)");
  script_cve_id("CVE-2007-4772", "CVE-2016-0766", "CVE-2016-0773");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 20:09:00 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for postgresql93 (SUSE-SU-2016:0539-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql93 fixes the following issues:

  - Security and bugfix release 9.3.11:

  * Fix infinite loops and buffer-overrun problems in regular expressions
  (CVE-2016-0773, bsc#966436).

  * Fix regular-expression compiler to handle loops of constraint arcs
  (CVE-2007-4772).

  * Prevent certain PL/Java parameters from being set by non-superusers
  (CVE-2016-0766, bsc#966435).

  * Fix many issues in pg_dump with specific object types

  * Prevent over-eager pushdown of HAVING clauses for GROUPING SETS

  * Fix deparsing error with ON CONFLICT ... WHERE clauses

  * Fix tableoid errors for postgres_fdw

  * Prevent floating-point exceptions in pgbench

  * Make \det search Foreign Table names consistently

  * Fix quoting of domain constraint names in pg_dump

  * Prevent putting expanded objects into Const nodes

  * Allow compile of PL/Java on Windows

  * Fix 'unresolved symbol' errors in PL/Python execution

  * Allow Python2 and Python3 to be used in the same database

  * Add support for Python 3.5 in PL/Python

  * Fix issue with subdirectory creation during initdb

  * Make pg_ctl report status correctly on Windows

  * Suppress confusing error when using pg_receivexlog with older servers

  * Multiple documentation corrections and additions

  * Fix erroneous hash calculations in gin_extract_jsonb_path()");

  script_tag(name:"affected", value:"postgresql93 on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"SUSE-SU", value:"2016:0539-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.11~14.2", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.11~14.2", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.11~14.2", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.11~14.2", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.11~14.2", rls:"SLES12.0SP0"))) {
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
