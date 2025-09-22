# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63375");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2005-0706");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2008-11956 (libcdaudio)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"libcdaudio is a library designed to provide functions to control
operation of a CD-ROM when playing audio CDs.  It also contains
functions for CDDB and CD Index lookup.

Update Information:

This update fixes a potential buffer overflow caused by large amount of CDDB
replies (CVE-2005-0706).

ChangeLog:

  * Sat Dec 27 2008 Axel Thimm  - 0.99.12p2-11

  - Fix CVE-2005-0706.

  * Wed May 21 2008 Tom spot Callaway  - 0.99.12p2-10

  - took COPYING out of doc (it is simply wrong)

  - fixed license tag");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libcdaudio' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2008-11956");
  script_tag(name:"summary", value:"The remote host is missing an update to libcdaudio
announced via advisory FEDORA-2008-11956.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=470552");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
