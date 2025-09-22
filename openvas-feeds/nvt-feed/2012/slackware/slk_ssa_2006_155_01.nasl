# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56861");
  script_cve_id("CVE-2006-1516", "CVE-2006-1517", "CVE-2006-2753");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2006-155-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-155-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.599377");
  script_xref(name:"URL", value:"http://lists.mysql.com/announce/359");
  script_xref(name:"URL", value:"http://lists.mysql.com/announce/364");
  script_xref(name:"URL", value:"http://lists.mysql.com/announce/365");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the SSA:2006-155-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mysql packages are available for Slackware 9.1, 10.0, 10.1,
10.2 and -current to fix security issues.


The MySQL packages shipped with Slackware 9.1, 10.0, and 10.1
may possibly leak sensitive information found in uninitialized
memory to authenticated users. This is fixed in the new packages,
and was already patched in Slackware 10.2 and -current.
Since the vulnerabilities require a valid login and/or access to the
database server, the risk is moderate. Slackware does not provide
network access to a MySQL database by default.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database.
Fixes that affect Slackware 9.1, 10.0, and 10.1:
 [links moved to references]


The MySQL packages in Slackware 10.2 and -current have been
upgraded to MySQL 4.1.20 (Slackware 10.2) and MySQL 5.0.22
(Slackware -current) to fix an SQL injection vulnerability.

For more details, see the MySQL 4.1.20 release announcement here:
 [link moved to references]
And the MySQL 5.0.22 release announcement here:
 [link moved to references]
The CVE entry for this issue can be found here:
 [link moved to references]


Here are the details from the Slackware 10.1 ChangeLog:
+--------------------------+
patches/packages/mysql-4.0.27-i486-1_slack10.1.tgz:
 Upgraded to mysql-4.0.27.
 This fixes some minor security issues with possible information leakage.
 Note that the information leakage bugs require that the attacker have
 access to an account on the database. Also note that by default,
 Slackware's rc.mysqld script does *not* allow access to the database
 through the outside network (it uses the --skip-networking option).
 If you've enabled network access to MySQL, it is a good idea to filter
 the port (3306) to prevent access from unauthorized machines.
 For more details, see the MySQL 4.0.27 release announcement here:
 [link moved to references]
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+

Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/mysql-4.1.20-i486-1_slack10.2.tgz:
 Upgraded to mysql-4.1.20. This fixes an SQL injection vulnerability.
 For more details, see the MySQL 4.1.20 release announcement here:
 [link moved to references]
 The CVE entry for this issue will be found here:
 [link moved to references]
+--------------------------+");

  script_tag(name:"affected", value:"'mysql' package(s) on Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK10.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"mysql", ver:"4.0.27-i486-1_slack10.0", rls:"SLK10.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"mysql", ver:"4.0.27-i486-1_slack10.1", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"mysql", ver:"4.1.20-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"mysql", ver:"4.0.27-i486-1_slack9.1", rls:"SLK9.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"mysql", ver:"5.0.22-i486-1", rls:"SLKcurrent"))) {
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
