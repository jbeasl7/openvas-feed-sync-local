# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66579");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2009-4427");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-13598 (phpldapadmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Upgrade to 1.2.0.4
A vulnerability has been discovered on phpLDAPadmin
version 1.1.x, which can be exploited by malicious people
to disclose sensitive information.
This update upgrades phpldapadmin to the latest version 1.2.0.4,
which is not affected.

ChangeLog:

  * Wed Dec 23 2009 Dmitry Butskoy  - 1.2.0.4-1

  - Upgrade to 1.2.0.4. Fixes #549559

  - Allow local IPv6 address by default");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update phpldapadmin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37327");
  script_tag(name:"summary", value:"The remote host is missing an update to phpldapadmin
announced via advisory FEDORA-2009-13598.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=549559");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
