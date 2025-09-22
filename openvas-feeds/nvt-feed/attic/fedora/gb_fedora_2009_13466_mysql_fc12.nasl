# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66573");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-4019", "CVE-2009-4028");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 12 FEDORA-2009-13466 (mysql)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files.

Update Information:

  - Update to MySQL 5.1.41, for various fixes including security fixes

  - Stop waiting during service mysqld start if mysqld_safe exits

ChangeLog:

  * Thu Dec 17 2009 Tom Lane  5.1.41-2

  - Update to MySQL 5.1.41, for various fixes including fixes for CVE-2009-4019
Related: #540906

  - Stop waiting during service mysqld start if mysqld_safe exits
Resolves: #544095

  * Tue Nov 10 2009 Tom Lane  5.1.40-1

  - Update to MySQL 5.1.40, for various fixes

  - Do not force the --log-error setting in mysqld init script
Resolves: #533736");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update mysql' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13466");
  script_tag(name:"summary", value:"The remote host is missing an update to mysql
announced via advisory FEDORA-2009-13466.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=540906");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=541233");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
