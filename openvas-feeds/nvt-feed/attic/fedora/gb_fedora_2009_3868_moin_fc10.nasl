# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63881");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2008-0781", "CVE-2008-3381", "CVE-2009-0260", "CVE-2009-0312");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-3868 (moin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update moin to 1.6.4. Fix the following CVEs: CVE-2008-0781 (again),
CVE-2008-3381, CVE-2009-0260, CVE-2009-0312. Fix AttachFile escaping problems,
upstream 1.7 changeset 5f51246a4df1 backported.
ChangeLog:

  * Mon Apr 20 2009 Ville-Pekka Vainio  1.6.4-1

  - Update to 1.6.4

  - CVE-2008-3381 fixed upstream

  - Re-fix CVE-2008-0781, upstream seems to have dropped the fix in 1.6,
used part of upstream 1.5 db212dfc58ef, backported upstream 1.7 5f51246a4df1
and 269a1fbc3ed7

  - Fix CVE-2009-0260, patch from Debian etch

  - Fix CVE-2009-0312

  - Fix AttachFile escaping problems, backported upstream 1.7 5c4043e651b3");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update moin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3868");
  script_tag(name:"summary", value:"The remote host is missing an update to moin
announced via advisory FEDORA-2009-3868.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=457362");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=481547");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=432748");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=482791");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
