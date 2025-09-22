# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881824");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-11-08 10:52:36 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2013-0255", "CVE-2013-1900");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("CentOS Update for postgresql84 CESA-2013:1475 centos5");

  script_tag(name:"affected", value:"postgresql84 on CentOS 5");
  script_tag(name:"insight", value:"PostgreSQL is an advanced object-relational database management system
(DBMS).

An array index error, leading to a heap-based out-of-bounds buffer read
flaw, was found in the way PostgreSQL performed certain error processing
using enumeration types. An unprivileged database user could issue a
specially crafted SQL query that, when processed by the server component of
the PostgreSQL service, would lead to a denial of service (daemon crash) or
disclosure of certain portions of server memory. (CVE-2013-0255)

A flaw was found in the way the pgcrypto contrib module of PostgreSQL
(re)initialized its internal random number generator. This could lead to
random numbers with less bits of entropy being used by certain pgcrypto
functions, possibly allowing an attacker to conduct other attacks.
(CVE-2013-1900)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Sumit Soni via Secunia SVCRP as the original
reporter of CVE-2013-0255, and Marko Kreen as the original reporter of
CVE-2013-1900.

These updated packages upgrade PostgreSQL to version 8.4.18, which fixes
these issues as well as several non-security issues. Refer to the
PostgreSQL Release Notes for a full list of changes:

After installing this update, it is advisable to rebuild, using the REINDEX
command, Generalized Search Tree (GiST) indexes that meet one or more of
the following conditions:

  - - GiST indexes on box, polygon, circle, or point columns

  - - GiST indexes for variable-width data types, that is text, bytea, bit, and
numeric

  - - GiST multi-column indexes

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the postgresql
service is running, it will be automatically restarted after installing
this update.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1475");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-October/019995.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql84'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"postgresql84", rpm:"postgresql84~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-contrib", rpm:"postgresql84-contrib~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-devel", rpm:"postgresql84-devel~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-docs", rpm:"postgresql84-docs~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-libs", rpm:"postgresql84-libs~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plperl", rpm:"postgresql84-plperl~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plpython", rpm:"postgresql84-plpython~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-pltcl", rpm:"postgresql84-pltcl~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-python", rpm:"postgresql84-python~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-server", rpm:"postgresql84-server~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-tcl", rpm:"postgresql84-tcl~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-test", rpm:"postgresql84-test~8.4.18~1.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
