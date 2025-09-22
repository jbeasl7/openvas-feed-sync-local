# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871431");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-08-18 06:48:59 +0200 (Tue, 18 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for sqlite RHSA-2015:1635-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"SQLite is a C library that implements an SQL database engine. A large
subset of SQL92 is supported. A complete database is stored in a single
disk file. The API is designed for convenience and ease of use.
Applications that link against SQLite can enjoy the power and flexibility
of an SQL database without the administrative hassles of supporting a
separate database server.

A flaw was found in the way SQLite handled dequoting of collation-sequence
names. A local attacker could submit a specially crafted COLLATE statement
that would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3414)

It was found that SQLite's sqlite3VdbeExec() function did not properly
implement comparison operators. A local attacker could submit a specially
crafted CHECK statement that would crash the SQLite process, or have other
unspecified impacts. (CVE-2015-3415)

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions.
A local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)

All sqlite users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"affected", value:"sqlite on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1635-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-August/msg00028.html");
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

  if ((res = isrpmvuln(pkg:"sqlite", rpm:"sqlite~3.7.17~6.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sqlite-debuginfo", rpm:"sqlite-debuginfo~3.7.17~6.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sqlite-devel", rpm:"sqlite-devel~3.7.17~6.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
