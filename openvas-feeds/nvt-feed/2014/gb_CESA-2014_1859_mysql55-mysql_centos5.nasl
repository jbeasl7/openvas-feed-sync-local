# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882084");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-18 06:39:13 +0100 (Tue, 18 Nov 2014)");
  script_cve_id("CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4243", "CVE-2014-4258",
                "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463",
                "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6484", "CVE-2014-6505",
                "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551",
                "CVE-2014-6555", "CVE-2014-6559");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_name("CentOS Update for mysql55-mysql CESA-2014:1859 centos5");

  script_tag(name:"summary", value:"Check the version of mysql55-mysql");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL
database server. It consists of the MySQL server daemon (mysqld) and many client
programs and libraries.

This update fixes several vulnerabilities in the MySQL database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory page, listed in the References section. (CVE-2014-2494,
CVE-2014-4207, CVE-2014-4243, CVE-2014-4258, CVE-2014-4260, CVE-2014-4287,
CVE-2014-4274, CVE-2014-6463, CVE-2014-6464, CVE-2014-6469, CVE-2014-6484,
CVE-2014-6505, CVE-2014-6507, CVE-2014-6520, CVE-2014-6530, CVE-2014-6551,
CVE-2014-6555, CVE-2014-6559)

These updated packages upgrade MySQL to version 5.5.40. Refer to the MySQL
Release Notes listed in the References section for a complete list of
changes.

All MySQL users should upgrade to these updated packages, which correct
these issues. After installing this update, the MySQL server daemon
(mysqld) will be restarted automatically.");
  script_tag(name:"affected", value:"mysql55-mysql on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:1859");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-November/020762.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"mysql55-mysql", rpm:"mysql55-mysql~5.5.40~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-bench", rpm:"mysql55-mysql-bench~5.5.40~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-devel", rpm:"mysql55-mysql-devel~5.5.40~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-libs", rpm:"mysql55-mysql-libs~5.5.40~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-server", rpm:"mysql55-mysql-server~5.5.40~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql55-mysql-test", rpm:"mysql55-mysql-test~5.5.40~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
