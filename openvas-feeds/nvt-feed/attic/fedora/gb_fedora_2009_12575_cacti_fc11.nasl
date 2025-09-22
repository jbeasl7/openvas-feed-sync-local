# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66584");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-4032");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 11 FEDORA-2009-12575 (cacti)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This fix contains several official patches from cacti:
    Command Line Add Graphs Syntax
    SNMP Invalid Responses
    Template Import/Export Duplication
    Cross-Site Scripting Fixes

ChangeLog:

  * Tue Dec  1 2009 Mike McGrath  - 0.8.7e-3

  - Pulling in some official patches

  - #541279

  - #541962

  * Sun Aug 16 2009 Mike McGrath  - 0.8.7e-1

  - Upstream released new version

  * Fri Jul 24 2009 Fedora Release Engineering  - 0.8.7d-4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update cacti' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12575");
  script_tag(name:"summary", value:"The remote host is missing an update to cacti
announced via advisory FEDORA-2009-12575.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=541279");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
