# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63453");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2009-0386", "CVE-2009-0387");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-1343 (gstreamer-plugins-good)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"ChangeLog:

  * Mon Feb  2 2009 - Bastien Nocera  - 0.10.8-10

  - Patch for overflows in the QT demuxer (#481267)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gstreamer-plugins-good' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1343");
  script_tag(name:"summary", value:"The remote host is missing an update to gstreamer-plugins-good
announced via advisory FEDORA-2009-1343.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=481267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483736");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483737");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
