# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66561");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3388", "CVE-2009-3389");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-13333 (firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"For details, please visit the referenced advisories.

ChangeLog:

  * Wed Dec 16 2009 Jan Horak  - 3.5.6-1

  - Update to 3.5.6

  * Thu Nov  5 2009 Jan Horak  - 3.5.5-1

  - Update to 3.5.5

  * Mon Oct 26 2009 Jan Horak  - 3.5.4-1

  - Updated to 3.5.4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update firefox' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13333");
  script_tag(name:"summary", value:"The remote host is missing an update to firefox
announced via advisory FEDORA-2009-13333.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546694");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546720");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546726");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546724");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
