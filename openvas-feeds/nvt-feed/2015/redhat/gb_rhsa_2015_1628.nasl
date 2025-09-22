# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871428");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2014-6568", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382",
                "CVE-2015-0391", "CVE-2015-0411", "CVE-2015-0432", "CVE-2015-0433",
                "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505",
                "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2582",
                "CVE-2015-2620", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-4737",
                "CVE-2015-4752", "CVE-2015-4757");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-08-18 06:46:07 +0200 (Tue, 18 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mysql55-mysql RHSA-2015:1628-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql55-mysql'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
the MySQL server daemon (mysqld) and many client programs and libraries.

This update fixes several vulnerabilities in the MySQL database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory pages, listed in the References section. (CVE-2014-6568,
CVE-2015-0374, CVE-2015-0381, CVE-2015-0382, CVE-2015-0391, CVE-2015-0411,
CVE-2015-0432, CVE-2015-0433, CVE-2015-0441, CVE-2015-0499, CVE-2015-0501,
CVE-2015-0505, CVE-2015-2568, CVE-2015-2571, CVE-2015-2573, CVE-2015-2582,
CVE-2015-2620, CVE-2015-2643, CVE-2015-2648, CVE-2015-4737, CVE-2015-4752,
CVE-2015-4757)

These updated packages upgrade MySQL to version 5.5.45. Refer to the MySQL
Release Notes listed in the References section for a complete list of
changes.

All MySQL users should upgrade to these updated packages, which correct
these issues. After installing this update, the MySQL server daemon
(mysqld) will be restarted automatically.");
  script_tag(name:"affected", value:"mysql55-mysql on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1628-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-August/msg00022.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"mysql55-mysql", rpm:"mysql55-mysql~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-bench", rpm:"mysql55-mysql-bench~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-debuginfo", rpm:"mysql55-mysql-debuginfo~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-devel", rpm:"mysql55-mysql-devel~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-libs", rpm:"mysql55-mysql-libs~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-server", rpm:"mysql55-mysql-server~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-test", rpm:"mysql55-mysql-test~5.5.45~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
