# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64349");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2009-2284");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-7340 (phpMyAdmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"For details, on the issues addressed, please visit the
referenced security advisories.

ChangeLog:

  * Tue Jun 30 2009 Robert Scheck  3.2.0.1-1

  - Upstream released 3.2.0.1 (#508879)

  * Tue Jun 30 2009 Robert Scheck  3.2.0-1

  - Upstream released 3.2.0

  * Fri May 15 2009 Robert Scheck  3.1.5-1

  - Upstream released 3.1.5

  * Sat Apr 25 2009 Robert Scheck  3.1.4-1

  - Upstream released 3.1.4

  * Tue Apr 14 2009 Robert Scheck  3.1.3.2-1

  - Upstream released 3.1.3.2 (#495768)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update phpMyAdmin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35543");
  script_tag(name:"summary", value:"The remote host is missing an update to phpMyAdmin
announced via advisory FEDORA-2009-7340.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=508879");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
