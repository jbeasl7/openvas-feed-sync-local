# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871182");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-07-04 16:48:49 +0530 (Fri, 04 Jul 2014)");
  script_cve_id("CVE-2014-0384", "CVE-2014-2419", "CVE-2014-2430", "CVE-2014-2431",
                "CVE-2014-2432", "CVE-2014-2436", "CVE-2014-2438", "CVE-2014-2440");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("RedHat Update for mariadb RHSA-2014:0702-01");


  script_tag(name:"affected", value:"mariadb on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"insight", value:"MariaDB is a multi-user, multi-threaded SQL database server that is binary
compatible with MySQL.

This update fixes several vulnerabilities in the MariaDB database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory page, listed in the References section. (CVE-2014-2436,
CVE-2014-2440, CVE-2014-0384, CVE-2014-2419, CVE-2014-2430, CVE-2014-2431,
CVE-2014-2432, CVE-2014-2438)

These updated packages upgrade MariaDB to version 5.5.37. Refer to the
MariaDB Release Notes listed in the References section for a complete list
of changes.

All MariaDB users should upgrade to these updated packages, which correct
these issues. After installing this update, the MariaDB server daemon
(mysqld) will be restarted automatically.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0702-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-June/msg00026.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.37~1.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
