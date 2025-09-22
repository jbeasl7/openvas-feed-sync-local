# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63215");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2009-0135", "CVE-2009-0136");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-0550 (amarok)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

An update to the latest release, includes new features such
as queuing, playlist search and filtering as well as stop
after current track. And, long awaited and finally available:
sorting the collection by composer.

Also includes a security fix concerning the parsing of
malformed Audible digital audio files.

ChangeLog:

  * Fri Jan  9 2009 Rex Dieter  - 2.0.1.1-1

  - amarok-2.0.1.1

  * Tue Jan  6 2009 Rex Dieter  - 2.0.1-1

  - amarok-2.0.1

  * Tue Dec  9 2008 Rex Dieter  - 2.0-2

  - respin tarball");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update amarok' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0550");
  script_tag(name:"summary", value:"The remote host is missing an update to amarok
announced via advisory FEDORA-2009-0550.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479560");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
