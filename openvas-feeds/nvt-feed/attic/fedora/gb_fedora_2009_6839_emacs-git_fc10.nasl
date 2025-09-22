# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64292");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-2108");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-6839 (git)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes a Denial of Service vulnerability in git-daemon.  It also
fixes minor issues when using git-cvsimport and the formatting of the git-daemon
xinetd service description.

ChangeLog:

  * Fri Jun 19 2009 Todd Zullinger  - 1.6.0.6-4

  - Fix git-daemon hang on invalid input (CVE-2009-2108, bug 505761)

  - Ignore Branches output from cvsps-2.2b1 (bug 490602)

  - Escape newline in git-daemon xinetd description (bug 502393)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update git' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6839");
  script_tag(name:"summary", value:"The remote host is missing an update to git
announced via advisory FEDORA-2009-6839.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=505761");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502393");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490602");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
