# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63374");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2008-4959", "CVE-2008-5380", "CVE-2008-5703");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-1366 (gpsdrive)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Gpsdrive is a map-based navigation system.
It displays your position on a zoomable map
provided from a NMEA-capable GPS receiver. The maps are autoselected
for the best resolution, depending of your position, and the displayed
image can be zoomed. Maps can be downloaded from the Internet with one
mouse click. The program provides information about speed, direction,
bearing, arrival time, actual position, and target position.
Speech output is also available. MySQL is supported.

Update Information:

This update removes several helper scripts: geo-code, geo-nearest, and
gpssmswatch, which have been removed upstream due to security issues. This
update also has a fix for an issue with the splash screen.

ChangeLog:

  * Mon Feb  2 2009 Kevin Fenzi  - 2.09-7

  - fix for CVE-2008-4959 - bug 470241

  - fix for CVE-2008-5380 - bug 475478

  - fix for CVE-2008-5703 - bug 481702");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gpsdrive' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1366");
  script_tag(name:"summary", value:"The remote host is missing an update to gpsdrive
announced via advisory FEDORA-2009-1366.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=470241");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=481702");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=475478");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
