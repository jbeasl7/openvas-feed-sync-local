# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53245");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0911");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 556-1 (netkit-telnet)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20556-1");
  script_tag(name:"insight", value:"Michal Zalewski discovered a bug in the netkit-telnet server (telnetd)
whereby a remote attacker could cause the telnetd process to free an
invalid pointer.  This causes the telnet server process to crash,
leading to a straightforward denial of service (inetd will disable the
service if telnetd is crashed repeatedly), or possibly the execution
of arbitrary code with the privileges of the telnetd process (by
default, the 'telnetd' user).

For the stable distribution (woody) this problem has been fixed in
version 0.17-18woody1.

For the unstable distribution (sid) this problem has been fixed in
version 0.17-26.");

  script_tag(name:"solution", value:"We recommend that you upgrade your netkit-telnetpackage.");
  script_tag(name:"summary", value:"The remote host is missing an update to netkit-telnet announced via advisory DSA 556-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-556)' (OID: 1.3.6.1.4.1.25623.1.0.53260).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
