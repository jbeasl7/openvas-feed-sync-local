# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66143");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 11 FEDORA-2009-10329 (python-markdown2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update from 1.0.1.11 to 1.0.1.15, which fixes some issues, including these two
security-related bugs:

  - [Issue 30] Fix a possible XSS via JavaScript injection in a carefully
             crafted image reference (usage of double-quotes in the URL).

  - [Issue 29] Fix security hole in the md5-hashing scheme for handling HTML
             chunks during processing.

ChangeLog:

  * Thu Oct  8 2009 Thomas Moschny  - 1.0.1.15-1

  - Update to 1.0.1.15. Fixes three issues, two of them being security-related.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update python-markdown2' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10329");
  script_tag(name:"summary", value:"The remote host is missing an update to python-markdown2
announced via advisory FEDORA-2009-10329.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
