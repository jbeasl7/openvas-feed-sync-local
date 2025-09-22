# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64618");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2411");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-8432 (subversion)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update includes the latest stable release of Subversion, including several
enhancements, many bug fixes, and a fix for a security issue:
Matt Lewis reported multiple heap overflow flaws in Subversion
(servers and clients) when parsing binary deltas. Malicious users with
commit access to a vulnerable server could uses these flaws to cause a
heap overflow on the server running Subversion. A malicious Subversion
server could use these flaws to cause a heap overflow on vulnerable
clients when they attempt to checkout or update, resulting in a crash or,

ChangeLog:

  * Fri Aug  7 2009 Joe Orton  1.6.4-2

  - update to 1.6.4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update subversion' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8432");
  script_tag(name:"summary", value:"The remote host is missing an update to subversion
announced via advisory FEDORA-2009-8432.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514744");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
