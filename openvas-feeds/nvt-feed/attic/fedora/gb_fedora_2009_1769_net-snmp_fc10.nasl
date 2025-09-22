# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63409");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
  script_cve_id("CVE-2008-6123", "CVE-2008-4309");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-1769 (net-snmp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Building option:

  - -without tcp_wrappers : disable tcp_wrappers support

ChangeLog:

  * Mon Feb 16 2009 Jan Safranek  5.4.2.1-3

  - fix tcp_wrappers integration (CVE-2008-6123)

  * Mon Dec  1 2008 Jan Safranek  5.4.2.1-2

  - rebuild for fixed rpm (#473420)

  * Mon Nov  3 2008 Jan Safranek  5.4.2.1-1

  - explicitly require the right version and release of net-snmp and
net-snmp-libs

  - update to net-snmp-5.4.2.1 to fix CVE-2008-4309");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update net-snmp' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1769");
  script_tag(name:"summary", value:"The remote host is missing an update to net-snmp
announced via advisory FEDORA-2009-1769.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=485211");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
