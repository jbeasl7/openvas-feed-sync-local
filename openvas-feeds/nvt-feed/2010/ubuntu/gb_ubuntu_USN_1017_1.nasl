# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840533");
  script_cve_id("CVE-2010-2008", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_tag(name:"creation_date", value:"2010-11-16 13:49:48 +0000 (Tue, 16 Nov 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|6\.06\ LTS|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1017-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1017-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.1, mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) announced via the USN-1017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MySQL incorrectly handled certain requests with the
UPGRADE DATA DIRECTORY NAME command. An authenticated user could exploit
this to make MySQL crash, causing a denial of service. This issue only
affected Ubuntu 9.10 and 10.04 LTS. (CVE-2010-2008)

It was discovered that MySQL incorrectly handled joins involving a table
with a unique SET column. An authenticated user could exploit this to make
MySQL crash, causing a denial of service. This issue only affected Ubuntu
6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3677)

It was discovered that MySQL incorrectly handled NULL arguments to IN() or
CASE operations. An authenticated user could exploit this to make MySQL
crash, causing a denial of service. This issue only affected Ubuntu 9.10
and 10.04 LTS. (CVE-2010-3678)

It was discovered that MySQL incorrectly handled malformed arguments to the
BINLOG statement. An authenticated user could exploit this to make MySQL
crash, causing a denial of service. This issue only affected Ubuntu 9.10
and 10.04 LTS. (CVE-2010-3679)

It was discovered that MySQL incorrectly handled the use of TEMPORARY
InnoDB tables with nullable columns. An authenticated user could exploit
this to make MySQL crash, causing a denial of service. This issue only
affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3680)

It was discovered that MySQL incorrectly handled alternate reads from two
indexes on a table using the HANDLER interface. An authenticated user could
exploit this to make MySQL crash, causing a denial of service. This issue
only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2010-3681)

It was discovered that MySQL incorrectly handled use of EXPLAIN with
certain queries. An authenticated user could exploit this to make MySQL
crash, causing a denial of service. This issue only affected Ubuntu
6.06 LTS, 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3682)

It was discovered that MySQL incorrectly handled error reporting when using
LOAD DATA INFILE and would incorrectly raise an assert in certain
circumstances. An authenticated user could exploit this to make MySQL
crash, causing a denial of service. This issue only affected Ubuntu 9.10
and 10.04 LTS. (CVE-2010-3683)

It was discovered that MySQL incorrectly handled propagation during
evaluation of arguments to extreme-value functions. An authenticated user
could exploit this to make MySQL crash, causing a denial of service. This
issue only affected Ubuntu 8.04 LTS, 9.10, 10.04 LTS and 10.10.
(CVE-2010-3833)

It was discovered that MySQL incorrectly handled materializing a derived
table that required a temporary table for grouping. An authenticated user
could exploit this to make MySQL crash, causing a denial of service.
(CVE-2010-3834)

It was discovered that MySQL incorrectly handled certain user-variable
assignment expressions that are evaluated in a logical expression context.
An authenticated ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mysql-5.1, mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.41-3ubuntu12.7", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.49-1ubuntu8.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.15", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-3ubuntu5.8", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.37-1ubuntu5.5", rls:"UBUNTU9.10"))) {
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
