# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53307");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0025");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 229-1 (imp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20229-1");
  script_tag(name:"insight", value:"Jouko Pynnonen discovered a problem with IMP, a web based IMAP mail
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
fixed in version 2.2.6-5.1.

For the old stable distribution (potato) this problem has been
fixed in version 2.2.6-0.potato.5.1.

For the unstable distribution (sid) these problems have been fixed in
version 2.2.6-7.");

  script_tag(name:"solution", value:"We recommend that you upgrade your IMP packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to imp announced via advisory DSA 229-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-229)' (OID: 1.3.6.1.4.1.25623.1.0.53308).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
