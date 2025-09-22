# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53308");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0025");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 229-2 (imp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20229-2");
  script_tag(name:"insight", value:"The advisory DSA 229-1 contained a typo in one file which could cause
certain installations to fail suddenly.

For completeness, here is the original advisory text:

Jouko Pynnonen discovered a problem with IMP, a web based IMAP mail
program.  Using carefully crafted URLs a remote attacker is able to
inject SQL code into SQL queries without proper user authentication.
Even though results of SQL queries aren't directly readable from the
screen, an attacker might. update his mail signature to contain wanted
query results and then view it on the preferences page of IMP.

The impact of SQL injection depends heavily on the underlying database
and its configuration.  If PostgreSQL is used, it's possible to
execute multiple complete SQL queries separated by semicolons.  The
database contains session id's so the attacker might hijack sessions
of people currently logged in and read their mail.  In the worst case,
if the hordemgr user has the required privilege to use the COPY SQL
command (found in PostgreSQL at least), a remote user may read or
write to any file the database user (postgres) can.  The attacker may
then be able to run arbitrary shell commands by writing them to the
postgres user's ~/.psqlrc. They'd be run when the user starts the psql
command which under some configurations happens regularly from a cron
script.

For the current stable distribution (woody) this problem has been
fixed in version 2.2.6-5.2.

For the old stable distribution (potato) this problem has been
fixed in version 2.2.6-0.potato.5.2.

For the unstable distribution (sid) this problem will be fixed in
version 2.2.6-8.");

  script_tag(name:"solution", value:"We recommend that you upgrade your IMP packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to imp
announced via advisory DSA 229-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"imp", ver:"2.2.6-0.potato.5.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"imp", ver:"2.2.6-5.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
