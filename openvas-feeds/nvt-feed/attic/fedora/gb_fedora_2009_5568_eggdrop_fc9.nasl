# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64082");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2007-2807", "CVE-2009-1789");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-5568 (eggdrop)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

mod/server.mod/servmsg.c in Eggheads Eggdrop and Windrop 1.6.19 and earlier
allows remote attackers to cause a denial of service (crash) via a crafted
PRIVMSG that causes an empty string to trigger a negative string length copy.
NOTE: this issue exists because of an incorrect fix for CVE-2007-2807. The
current remote denial of service is tracked as CVE-2009-1789.

ChangeLog:

  * Tue May 26 2009 Robert Scheck  1.6.19-4

  - Added upstream ctcpfix to solve CVE-2009-1789 (#502650)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update eggdrop' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5568");
  script_tag(name:"summary", value:"The remote host is missing an update to eggdrop
announced via advisory FEDORA-2009-5568.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502650");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
