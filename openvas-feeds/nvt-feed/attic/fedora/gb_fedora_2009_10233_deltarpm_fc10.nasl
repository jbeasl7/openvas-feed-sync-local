# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65744");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
  script_cve_id("CVE-2005-1849");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-10233 (deltarpm)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

deltarpm prior to the current build ships with a bundled copy of zlib.  This
version of zlib has a known vulnerability with CVE identifier: CVE-2005-1849
This build of deltarpm patches the program to use the system zlib (which was
fixed when the vulnerability was first discovered) instead of the bundled copy.

ChangeLog:

  * Wed Sep 30 2009 Toshio Kuratomi  - 3.4-11.1

  - Build against the system zlib, not the bundled library.  This remedies the
fact that the included zlib is affected by CVE-2005-1849.

  - Fix cfile_detect_rsync() to detect rsync even if we don't have a zlib capable
of making rsync-friendly compressed files.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update deltarpm' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10233");
  script_tag(name:"summary", value:"The remote host is missing an update to deltarpm
announced via advisory FEDORA-2009-10233.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526432");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
