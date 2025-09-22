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
  script_oid("1.3.6.1.4.1.25623.1.0.850932");
  script_version("2021-10-18T12:03:37+0000");
  script_tag(name:"last_modification", value:"2021-10-18 12:03:37 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-10-16 14:39:25 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-8964", "CVE-2015-0433", "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-3152");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-24 13:51:00 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for mariadb (SUSE-SU-2015:1273-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:

  * Logjam attack: mysql uses 512 bit dh groups in SSL [bnc#934789]

  * CVE-2015-3152: mysql --ssl does not enforce SSL [bnc#924663]

  * CVE-2014-8964: heap buffer overflow [bnc#906574]

  * CVE-2015-2325: heap buffer overflow in compile_branch() [bnc#924960]

  * CVE-2015-2326: heap buffer overflow in pcre_compile2() [bnc#924961]

  * CVE-2015-0501: unspecified vulnerability related to Server:Compiling
  (CPU April 2015)

  * CVE-2015-2571: unspecified vulnerability related to Server:Optimizer
  (CPU April 2015)

  * CVE-2015-0505: unspecified vulnerability related to Server:DDL (CPU
  April 2015)

  * CVE-2015-0499: unspecified vulnerability related to Server:Federated
  (CPU April 2015)

  * CVE-2015-2568: unspecified vulnerability related to
  Server:Security:Privileges (CPU April 2015)

  * CVE-2015-2573: unspecified vulnerability related to Server:DDL (CPU
  April 2015)

  * CVE-2015-0433: unspecified vulnerability related to
  Server:InnoDB:DML (CPU April 2015)

  * CVE-2015-0441: unspecified vulnerability related to
  Server:Security:Encryption (CPU April 2015)");

  script_tag(name:"affected", value:"mariadb on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:1273-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r18", rpm:"libmysqlclient_r18~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r18-32bit", rpm:"libmysqlclient_r18-32bit~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.20~18.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.20~18.1", rls:"SLED12.0SP0"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.20~18.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.20~18.1", rls:"SLES12.0SP0"))) {
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
