# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63294");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-1187 (gedit)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Untrusted search path vulnerability in gedit's Python module allows local users
to execute arbitrary code via a Trojan horse Python file in the current working
directory, related to an erroneous setting of sys.path by the PySys_SetArgv
function.

ChangeLog:

  * Mon Jan 26 2009 Ray Strode  - 1:2.24.3-3

  - Fix bug 481556 in a more functional way

  * Mon Jan 26 2009 Ray Strode  - 1:2.24.3-2

  - Fix up python plugin path to close up a security attack
vectors (bug 481556).

  * Thu Jan 15 2009 Matthias Clasen  - 1:2.24.3-1

  - Update to 2.24.3");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gedit' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1187");
  script_tag(name:"summary", value:"The remote host is missing an update to gedit
announced via advisory FEDORA-2009-1187.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=481556");
  script_xref(name:"URL", value:"http://bugzilla.gnome.org/show_bug.cgi?id=569214");
  script_xref(name:"URL", value:"http://www.nabble.com/Bug-484305%3A-bicyclerepair%3A-bike.vim-imports-untrusted-python-files-from-cwd-td18848099.html");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
