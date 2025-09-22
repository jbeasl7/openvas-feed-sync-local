# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63378");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2009-0352", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0358", "CVE-2009-0353", "CVE-2009-0356", "CVE-2009-0357");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-1398 (xulrunner)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"XULRunner provides the XUL Runtime environment for Gecko applications.

Update Information:

Update to the new upstream Firefox 3.0.6 / XULRunner 1.9.0.6 fixing multiple
security issues.

This update also contains new builds of all applications
depending on Gecko libraries, built against the new version,
including the latest google gadgets upstream release.

ChangeLog:

  * Wed Feb  4 2009 Christopher Aillon  1.9.0.6-1

  - Update to 1.9.0.6

  * Thu Jan  8 2009 Martin Stransky  1.9.0.5-2

  - Copied mozilla-config.h to stable include dir (#478445)

  * Tue Dec 16 2008 Christopher Aillon  1.9.0.5-1

  - Update to 1.9.0.5");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xulrunner' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1398");
  script_tag(name:"summary", value:"The remote host is missing an update to xulrunner
announced via advisory FEDORA-2009-1398.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483139");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483142");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483143");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483150");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483141");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483144");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483145");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
