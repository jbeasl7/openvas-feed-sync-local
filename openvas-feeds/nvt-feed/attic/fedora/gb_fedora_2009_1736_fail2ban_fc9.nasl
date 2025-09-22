# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63407");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
  script_cve_id("CVE-2009-0362");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("Fedora Core 9 FEDORA-2009-1736 (fail2ban)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Fail2ban scans log files like /var/log/pwdfail or
/var/log/apache/error_log and bans IP that makes too many password
failures. It updates firewall rules to reject the IP address.

Update Information:

This updates fixes CVE-2009-0362.

ChangeLog:

  * Sat Feb 14 2009 Axel Thimm  - 0.8.3-18

  - Fix CVE-2009-0362 (Fedora bugs #485461, #485464, #485465, #485466).

  * Mon Dec  1 2008 Ignacio Vazquez-Abrams  - 0.8.3-17

  - Rebuild for Python 2.6

  * Sun Aug 24 2008 Axel Thimm  - 0.8.3-16

  - Update to 0.8.3.

  * Wed May 21 2008 Tom spot Callaway  - 0.8.2-15

  - fix license tag

  * Thu Mar 27 2008 Axel Thimm  - 0.8.2-14

  - Close on exec fixes by Jonathan Underwood.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update fail2ban' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1736");
  script_tag(name:"summary", value:"The remote host is missing an update to fail2ban
announced via advisory FEDORA-2009-1736.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=485461");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
