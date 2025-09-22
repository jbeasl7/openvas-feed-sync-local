# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63128");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
  script_cve_id("CVE-2008-4242");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 8 FEDORA-2009-0195 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes a security issue where an attacker could conduct cross-site
request forgery (CSRF) attacks and execute arbitrary FTP commands. It
also fixes some SSL shutdown issues seen with certain clients.

ChangeLog:

  * Fri Jan  2 2009 Matthias Saou  1.3.1-8

  - Update default configuration to have a lit of available modules and more
example configuration for them.

  - Include patches to fix TLS issues (#457280).

  * Fri Jan  2 2009 Matthias Saou  1.3.1-7

  - Add Debian patch to fix CSRF vulnerability (#464127, upstream #3115).");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update proftpd' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0195");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd
announced via advisory FEDORA-2009-0195.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=464127");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
