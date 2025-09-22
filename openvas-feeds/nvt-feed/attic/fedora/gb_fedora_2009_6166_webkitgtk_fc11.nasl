# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64396");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-0945");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-6166 (webkitgtk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

WebKitGTK+ 1.1.8 contains many bug-fixes and updates including spell-checking
support, enhanced error reporting, lots of ATK enhancements, support for copying
images to the clipboard, and a new printing API (since 1.1.5) that allows
applications better control and monitoring of the printing process.    Also, a
potential buffer overflow  in SVGList::insertItemBefore has been fixed
(CVE-2009-0945). The JIT compiler is now enabled by default for x86_64
systems.

ChangeLog:

  * Fri May 29 2009 Peter Gordon  - 1.1.8-1

  - Update to new upstream release (1.1.8)

  * Thu May 28 2009 Peter Gordon  - 1.1.7-1

  - Update to new upstream release (1.1.7)

  - Remove jit build conditional. (JIT is now enabled by default on platforms
which support it: currently 32- and 64-bit x86.)

  - Fix installation of the GtkLauncher demo program so that it
is a binary and not a script. (Fixes bug #443048.)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update webkitgtk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6166");
  script_tag(name:"summary", value:"The remote host is missing an update to webkitgtk
announced via advisory FEDORA-2009-6166.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502673");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=443048");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484335");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
