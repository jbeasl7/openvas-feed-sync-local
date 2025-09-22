# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63263");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-5262");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-0856 (DevIL)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

  - Fix missing symbols (rh 480269)  - Fix off by one error in CVE-2008-5262 check
(rh 479864)

ChangeLog:

  * Mon Jan 19 2009 Hans de Goede  1.7.5-2

  - Fix missing symbols (rh 480269)

  - Fix off by one error in CVE-2008-5262 check (rh 479864)

  * Tue Jan 13 2009 Hans de Goede  1.7.5-1

  - Update to latest upstream: 1.7.5

  - Add patch to fix CVE-2008-5262");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update DevIL' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0856");
  script_tag(name:"summary", value:"The remote host is missing an update to DevIL
announced via advisory FEDORA-2009-0856.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479864");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
