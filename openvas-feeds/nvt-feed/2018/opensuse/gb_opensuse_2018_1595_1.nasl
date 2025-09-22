# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852040");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-2755", "CVE-2018-2759", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2777", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2786", "CVE-2018-2787", "CVE-2018-2810", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 17:02:00 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-10-26 06:36:20 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for mariadb (openSUSE-SU-2018:1595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:1595-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the openSUSE-SU-2018:1595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb to version 10.2.15 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-2767: Enforse use of SSL/TLS in embedded server library (Return
  of BACKRONYM) (bsc#1088681).

  - CVE-2018-2786: Vulnerability in the MySQL Server component of Oracle
  MySQL (subcomponent: InnoDB). Easily exploitable vulnerability allowed
  high privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server as well as unauthorized update,
  insert or delete access to some of MySQL Server accessible data
  (bsc#1089987).

  - CVE-2018-2759: Vulnerability in the MySQL Server component of Oracle
  MySQL (subcomponent: InnoDB). Easily exploitable vulnerability allowed
  high privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server (bsc#1089987).

  - CVE-2018-2777: Vulnerability in the MySQL Server component of Oracle
  MySQL (subcomponent: InnoDB). Easily exploitable vulnerability allowed
  high privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server (bsc#1089987).

  - CVE-2018-2810: Vulnerability in the MySQL Server component of Oracle
  MySQL (subcomponent: InnoDB). Easily exploitable vulnerability allowed
  high privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server (bsc#1089987).

  - CVE-2018-2782: Vulnerability in the MySQL Server component of Oracle
  MySQL (subcomponent: InnoDB). Easily exploitable vulnerability allowed
  low privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server (bsc#1089987, bsc#1090518).

  - CVE-2018-2784: Vulnerability in the MySQL Server component of Oracle
  MySQL (subcomponent: InnoDB). Easily exploitable vulnerability allowed
  low privileged attacker with network access via multiple p ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"mariadb on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"libmysqld-devel", rpm:"libmysqld-devel~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld19", rpm:"libmysqld19~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqld19-debuginfo", rpm:"libmysqld19-debuginfo~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench-debuginfo", rpm:"mariadb-bench-debuginfo~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-galera", rpm:"mariadb-galera~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test-debuginfo", rpm:"mariadb-test-debuginfo~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.2.15~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
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
