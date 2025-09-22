# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64706");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2621", "CVE-2009-2622");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-8327 (squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Fixes several denial of service issues which could allow an attacker to
stop the Squid service.  CVE-2009-2621, CVE-2009-2622

ChangeLog:

  * Tue Aug  4 2009 Henrik Nordstrom  - 7:3.0.STABLE18-1

  - Update to 3.0.STABLE18

  * Sat Aug  1 2009 Henrik Nordstrom  - 7:3.0.STABLE17-3

  - Squid Bug #2728: regression: assertion failed: http.cc:705: !eof

  * Mon Jul 27 2009 Henrik Nordstrom  - 7:3.0.STABLE17-1

  - Bug #514014, update to 3.0.STABLE17 fixing the denial of service issues
mentioned in Squid security advisory SQUID-2009_2.

  * Mon Jul 13 2009 Henrik Nordstrom  - 7:3.0.STABLE16-2

  - Upgrade to latest upstream");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update squid' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8327");
  script_tag(name:"summary", value:"The remote host is missing an update to squid
announced via advisory FEDORA-2009-8327.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514013");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
