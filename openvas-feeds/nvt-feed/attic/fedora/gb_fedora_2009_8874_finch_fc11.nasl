# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64727");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2694");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8874 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

2.6.1 fixes an issue where pidgin can crash if you are sent a certain type of
URL over Yahoo.

ChangeLog:

  * Wed Aug 19 2009 Warren Togami  2.6.1-1

  - 2.6.1: Fix a crash when some users send you a link in a Yahoo IM

  * Tue Aug 18 2009 Warren Togami  2.6.0-1

  - CVE-2009-2694

  - Voice and Video support via farsight2 (Fedora 11+)

  - Numerous other bug fixes

  * Thu Aug  6 2009 Warren Togami  2.6.0-0.11.20090812

  - new snapshot at the request of maiku

  * Thu Aug  6 2009 Warren Togami  2.6.0-0.10.20090806

  - new snapshot - theoretically better sound quality in voice chat

  * Tue Aug  4 2009 Warren Togami  2.6.0-0.9.20090804

  - new snapshot");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update pidgin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8874");
  script_tag(name:"summary", value:"The remote host is missing an update to pidgin
announced via advisory FEDORA-2009-8874.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
