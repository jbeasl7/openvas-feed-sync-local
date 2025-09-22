# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63990");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
  script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3599 (wireshark)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

upgrade to wireshark-1.0.7 fixes various security flaws.

ChangeLog:

  * Fri Apr 10 2009 Radek Vokal  1.0.7-1

  - upgrade to 1.0.7

  - Several security vulnerabilities have been fixed
(Profinet, CPHAP and LDAP dissectors could crash)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update wireshark' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3599");
  script_tag(name:"summary", value:"The remote host is missing an update to wireshark
announced via advisory FEDORA-2009-3599.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=493973");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495119");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495121");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
