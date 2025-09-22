# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64408");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-2369");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-7755 (compat-wxGTK26)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Added rediffed fix for CVE-2009-2369 as found in wxGTK 2.8.10
ChangeLog:

  * Wed Jul 15 2009 Michael Schwendt  - 2.6.4-10

  - apply rediffed fix for CVE-2009-2369 (#511279)

  * Thu Jun 11 2009 Michael Schwendt  - 2.6.4-9

  - glib2 2.21.1's gio in Rawhide F-12 introduces a GSocket that
conflicts with wxGTK's GSocket class (gsocket.h): reduce the glib/gdk
headers that are included during build to avoid conflicting redefinitions

  * Sun Jun  7 2009 Michael Schwendt  - 2.6.4-8

  - target sparcv9 => setup-sparc.h");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update compat-wxGTK26' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7755");
  script_tag(name:"summary", value:"The remote host is missing an update to compat-wxGTK26
announced via advisory FEDORA-2009-7755.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=511279");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
