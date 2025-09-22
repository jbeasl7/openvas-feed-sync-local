# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66328");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
  script_cve_id("CVE-2009-4022");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 12 FEDORA-2009-12233 (bind)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to 9.6.1-P2 release which contains following fix:

  * Additional section of response could be cached without successful
DNSSEC validation even if DNSSEC validation is enabled

ChangeLog:

  * Wed Nov 25 2009 Adam Tkac  32:9.6.1-13.P2

  - update to 9.6.1-P2 (CVE-2009-4022)

  * Thu Oct  8 2009 Adam Tkac  32:9.6.1-12.P1

  - don't package named-bootconf utility, it is very outdated and unneeded");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update bind' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12233");
  script_tag(name:"summary", value:"The remote host is missing an update to bind
announced via advisory FEDORA-2009-12233.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=538744");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
