# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016701.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880577");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0442");
  script_cve_id("CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1850");
  script_name("CentOS Update for mysql CESA-2010:0442 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mysql on CentOS 5");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  A buffer overflow flaw was found in the way MySQL handled the parameters of
  the MySQL COM_FIELD_LIST network protocol command (this command is sent
  when a client uses the MySQL mysql_list_fields() client library function).
  An authenticated database user could send a request with an excessively
  long table name to cause a temporary denial of service (mysqld crash) or,
  potentially, execute arbitrary code with the privileges of the database
  server. (CVE-2010-1850)

  A directory traversal flaw was found in the way MySQL handled the
  parameters of the MySQL COM_FIELD_LIST network protocol command. An
  authenticated database user could use this flaw to obtain descriptions of
  the fields of an arbitrary table using a request with a specially-crafted
  table name. (CVE-2010-1848)

  A flaw was discovered in the way MySQL handled symbolic links to tables
  created using the DATA DIRECTORY and INDEX DIRECTORY directives in CREATE
  TABLE statements. An attacker with CREATE and DROP table privileges, and
  shell access to the database server, could use this flaw to remove data and
  index files of tables created by other database users using the MyISAM
  storage engine. (CVE-2010-1626)

  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~4.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~4.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~4.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~4.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~4.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
