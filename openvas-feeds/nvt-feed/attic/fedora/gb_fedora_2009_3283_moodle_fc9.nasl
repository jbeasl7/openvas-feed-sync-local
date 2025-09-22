# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/502231/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34278");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8297");
  script_oid("1.3.6.1.4.1.25623.1.0.63727");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2009-1171", "CVE-2009-0499", "CVE-2008-5153", "CVE-2008-4796");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3283 (moodle)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Moodle is a course management system (CMS) - a free, Open Source software
package designed using sound pedagogical principles, to help educators create
effective online learning communities.

Update Information:

CVE-2009-1171:  The TeX filter in Moodle 1.6 before 1.6.9+, 1.7 before 1.7.7+,
1.8  before 1.8.9, and 1.9 before 1.9.5 allows user-assisted attackers to  read
arbitrary files via an input command in a $$ sequence, which  causes LaTeX to
include the contents of the file.

ChangeLog:

  * Wed Apr  1 2009 Jon Ciesla  - 1.9.4-6

  - Patch for CVE-2009-1171, BZ 493109.

  * Tue Mar 24 2009 Jon Ciesla  - 1.9.4-5

  - Update for freefont->gnu-free-fonts change.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update moodle' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3283");
  script_tag(name:"summary", value:"The remote host is missing an update to moodle
announced via advisory FEDORA-2009-3283.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=493109");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
