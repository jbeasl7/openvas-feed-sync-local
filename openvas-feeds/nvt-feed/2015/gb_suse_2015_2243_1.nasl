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
  script_oid("1.3.6.1.4.1.25623.1.0.851141");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-12-11 05:50:43 +0100 (Fri, 11 Dec 2015)");
  script_cve_id("CVE-2015-0286", "CVE-2015-0288", "CVE-2015-1789", "CVE-2015-1793",
                "CVE-2015-3152", "CVE-2015-4730", "CVE-2015-4766", "CVE-2015-4792",
                "CVE-2015-4800", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816",
                "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4833",
                "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4862",
                "CVE-2015-4864", "CVE-2015-4866", "CVE-2015-4870", "CVE-2015-4879",
                "CVE-2015-4890", "CVE-2015-4895", "CVE-2015-4904", "CVE-2015-4905",
                "CVE-2015-4910", "CVE-2015-4913");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Security (openSUSE-SU-2015:2243-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL was updated to 5.6.27 to fix security issues and bugs.

  The following vulnerabilities were fixed as part of the upstream release
  [boo#951391]: CVE-2015-1793, CVE-2015-0286, CVE-2015-0288, CVE-2015-1789,
  CVE-2015-4730, CVE-2015-4766, CVE-2015-4792, CVE-2015-4800, CVE-2015-4802,
  CVE-2015-4815, CVE-2015-4816, CVE-2015-4819, CVE-2015-4826, CVE-2015-4830,
  CVE-2015-4833, CVE-2015-4836, CVE-2015-4858, CVE-2015-4861, CVE-2015-4862,
  CVE-2015-4864, CVE-2015-4866, CVE-2015-4870, CVE-2015-4879, CVE-2015-4890,
  CVE-2015-4895, CVE-2015-4904, CVE-2015-4905, CVE-2015-4910, CVE-2015-4913

  Details on these and other changes can be found at the linked vendor news.

  The following security relevant changes are included additionally:

  * CVE-2015-3152: MySQL lacked SSL enforcement. Using

  - -ssl-verify-server-cert and --ssl[-*] implies that the ssl connection
  is required. The mysql client will now print an error if ssl is
  required, but the server can not handle a ssl connection [boo#924663],
  [boo#928962]");

  script_tag(name:"affected", value:"Security on openSUSE 13.2, openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:2243-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE13\.2|openSUSE13\.1)");

  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-27.html");

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
  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.27~2.12.1", rls:"openSUSE13.2"))) {
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
  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18", rpm:"libmysql56client18~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo", rpm:"libmysql56client18-debuginfo~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18", rpm:"libmysql56client_r18~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server", rpm:"mysql-community-server~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench", rpm:"mysql-community-server-bench~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-bench-debuginfo", rpm:"mysql-community-server-bench-debuginfo~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client", rpm:"mysql-community-server-client~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-client-debuginfo", rpm:"mysql-community-server-client-debuginfo~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debuginfo", rpm:"mysql-community-server-debuginfo~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-debugsource", rpm:"mysql-community-server-debugsource~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-errormessages", rpm:"mysql-community-server-errormessages~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test", rpm:"mysql-community-server-test~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-test-debuginfo", rpm:"mysql-community-server-test-debuginfo~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools", rpm:"mysql-community-server-tools~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-community-server-tools-debuginfo", rpm:"mysql-community-server-tools-debuginfo~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-32bit", rpm:"libmysql56client18-32bit~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client18-debuginfo-32bit", rpm:"libmysql56client18-debuginfo-32bit~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql56client_r18-32bit", rpm:"libmysql56client_r18-32bit~5.6.27~7.13.1", rls:"openSUSE13.1"))) {
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
