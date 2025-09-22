# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63788");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0887");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3204 (pam)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to new minor upstream release. Minor security issue fixes and bug fixes.
ChangeLog:

  * Mon Mar 30 2009 Tomas Mraz  1.0.4-4

  - replace libtool to drop unneeded /lib64 rpath

  * Thu Mar 26 2009 Tomas Mraz  1.0.4-3

  - replace all std descriptors when calling helpers (#491471)

  * Tue Mar 17 2009 Tomas Mraz  1.0.4-2

  - update to new upstream minor release (bugfixes and minor security fixes)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update pam' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3204");
  script_tag(name:"summary", value:"The remote host is missing an update to pam
announced via advisory FEDORA-2009-3204.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=489932");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487216");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
