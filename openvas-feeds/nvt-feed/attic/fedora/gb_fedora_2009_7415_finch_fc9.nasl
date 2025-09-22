# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64355");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
  script_cve_id("CVE-2009-1889");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 9 FEDORA-2009-7415 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Several important bug fixes:  - More fixes for Yahoo protocol 16  - MSN,
MySpace, XMPP  - CVE-2009-1889

ChangeLog:

  * Sun Jun 28 2009 Warren Togami  2.5.8-1

  - 2.5.8 with several important bug fixes

  * Mon Jun 22 2009 Warren Togami  2.5.7-2

  - glib2 compat with RHEL-4

  * Sat Jun 20 2009 Warren Togami  2.5.7-1

  - 2.5.7 with Yahoo Protocol 16 support

  * Wed May 20 2009 Stu Tomlinson  2.5.6-1

  - 2.5.6

  * Mon Apr 20 2009 Warren Togami  2.5.5-3

  - F12+ removed krb4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update pidgin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7415");
  script_tag(name:"summary", value:"The remote host is missing an update to pidgin
announced via advisory FEDORA-2009-7415.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=508738");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
