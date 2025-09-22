# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63121");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
  script_cve_id("CVE-2003-0063", "CVE-2003-0071", "CVE-2008-2383");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 8 FEDORA-2009-0154 (xterm)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes the following security issue:    CRLF injection vulnerability
in xterm allows user-assisted attackers to execute arbitrary commands via LF
(aka \n) characters surrounding a command name within a Device Control Request
Status String (DECRQSS) escape sequence in a text file, a related issue to
CVE-2003-0063 and CVE-2003-0071.

ChangeLog:

  * Tue Jan  6 2009 Miroslav Lichvar  238-1

  - update to 238 (#479000, CVE-2008-2383)

  - set default values of allowWindowOps and allowFontOps resources to false");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xterm' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0154");
  script_tag(name:"summary", value:"The remote host is missing an update to xterm
announced via advisory FEDORA-2009-0154.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479000");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
