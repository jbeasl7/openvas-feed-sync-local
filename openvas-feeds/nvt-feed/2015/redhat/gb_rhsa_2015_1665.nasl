# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871435");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2015-0433", "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501",
                "CVE-2015-0505", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573",
                "CVE-2015-2582", "CVE-2015-2620", "CVE-2015-2643", "CVE-2015-2648",
                "CVE-2015-3152", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4757");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:M/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 19:47:00 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-08-25 07:59:09 +0200 (Tue, 25 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mariadb RHSA-2015:1665-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MariaDB is a multi-user, multi-threaded SQL database server that is binary
compatible with MySQL.

It was found that the MySQL client library permitted but did not require
a client to use SSL/TLS when establishing a secure connection to a MySQL
server using the '--ssl' option. A man-in-the-middle attacker
could use this flaw to strip the SSL/TLS protection from a connection
between a client and a server. (CVE-2015-3152)

This update fixes several vulnerabilities in the MariaDB database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory page, listed in the References section. (CVE-2015-0501,
CVE-2015-2568, CVE-2015-0499, CVE-2015-2571, CVE-2015-0433, CVE-2015-0441,
CVE-2015-0505, CVE-2015-2573, CVE-2015-2582, CVE-2015-2620, CVE-2015-2643,
CVE-2015-2648, CVE-2015-4737, CVE-2015-4752, CVE-2015-4757)

These updated packages upgrade MariaDB to version 5.5.44. Refer to the
MariaDB Release Notes listed in the References section for a complete list
of changes.

All MariaDB users should upgrade to these updated packages, which correct
these issues. After installing this update, the MariaDB server daemon
(mysqld) will be restarted automatically.");
  script_tag(name:"affected", value:"mariadb on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1665-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-August/msg00040.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.44~1.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
