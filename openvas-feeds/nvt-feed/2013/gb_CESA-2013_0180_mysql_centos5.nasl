# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019207.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881578");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-24 09:27:22 +0530 (Thu, 24 Jan 2013)");
  # nb: From the oracle cpujul2012 advisory: CVE-2012-1734 and CVE-2012-2749 are equivalent.
  script_cve_id("CVE-2012-1734", "CVE-2012-2749", "CVE-2012-5611", "CVE-2012-2122");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2013:0180");
  script_name("CentOS Update for mysql CESA-2013:0180 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mysql on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  A stack-based buffer overflow flaw was found in the user permission
  checking code in MySQL. An authenticated database user could use this flaw
  to crash the mysqld daemon or, potentially, execute arbitrary code with the
  privileges of the user running the mysqld daemon. (CVE-2012-5611)

  A flaw was found in the way MySQL calculated the key length when creating
  a sort order index for certain queries. An authenticated database user
  could use this flaw to crash the mysqld daemon. (CVE-2012-2749)

  This update also adds a patch for a potential flaw in the MySQL password
  checking function, which could allow an attacker to log into any MySQL
  account without knowing the correct password. This problem (CVE-2012-2122)
  only affected MySQL packages that use a certain compiler and C library
  optimization. It did not affect the mysql packages in Red Hat Enterprise
  Linux 5. The patch is being added as a preventive measure to ensure this
  problem cannot get exposed in future revisions of the mysql packages.
  (BZ#814605)

  All MySQL users should upgrade to these updated packages, which correct
  these issues. After installing this update, the MySQL server daemon
  (mysqld) will be restarted automatically.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.95~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.95~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.95~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.95~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.95~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
