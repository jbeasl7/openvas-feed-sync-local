# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63456");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2009-0415");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-1694 (trickle)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

New patch for CVE-2009-0415 Fix for #484065 - CVE-2009-0415 trickle: Possibility
to load arbitrary code from current working directory
ChangeLog:

  * Thu Feb 12 2009 Nicoleau Fabien  1.07-7

  - Replace sed with a patch for #484065 (CVE-2009-0415)

  * Fri Feb  6 2009 Nicoleau Fabien  1.07-6

  - Add a fix for bug #484065 (CVE-2009-0415)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update trickle' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1694");
  script_tag(name:"summary", value:"The remote host is missing an update to trickle
announced via advisory FEDORA-2009-1694.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484065");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
