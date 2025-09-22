# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63384");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2004-0918", "CVE-2009-0478");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 9 FEDORA-2009-1517 (squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"ChangeLog:

  * Thu Feb  5 2009 Jonathan Steffan  - 7:3.0.STABLE13-1

  - upgrade to latest upstream

  * Thu Jan 29 2009 Henrik Nordstrom  - 7:3.0.STABLE12-1

  - upgrade to latest upstream

  * Fri Dec 19 2008 Henrik Nordstrom  - 7:3.0.STABLE10-3

  - actually include the upstream bugfixes in the build

  * Fri Dec 19 2008 Henrik Nordstrom  - 7:3.0.STABLE10-2

  - upstream bugfixes for cache corruption and access.log response size errors");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update squid' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1517");
  script_tag(name:"summary", value:"The remote host is missing an update to squid
announced via advisory FEDORA-2009-1517.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484246");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
