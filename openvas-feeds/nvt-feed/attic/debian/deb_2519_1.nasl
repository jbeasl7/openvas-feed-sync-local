# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71496");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-4539", "CVE-2012-3571", "CVE-2012-3954");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-08-10 03:15:18 -0400 (Fri, 10 Aug 2012)");
  script_name("Debian Security Advisory DSA 2519-1 (isc-dhcp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202519-1");
  script_tag(name:"insight", value:"Several security vulnerabilities affecting ISC dhcpd, a server for
automatic IP address assignment, have been discovered.  Additionally, the
latest security update for isc-dhcp, DSA-2516-1, did not properly apply
the patches for CVE-2012-3571 and CVE-2012-3954.  This has been addressed
in this additional update.

CVE-2011-4539

BlueCat Networks discovered that it is possible to crash DHCP servers
configured to evaluate requests with regular expressions via crafted
DHCP request packets.

CVE-2012-3571

Markus Hietava of the Codenomicon CROSS project discovered that it is
possible to force the server to enter an infinite loop via messages with
malformed client identifiers.

CVE-2012-3954

Glen Eustace discovered that DHCP servers running in DHCPv6 mode
and possibly DHCPv4 mode suffer of memory leaks while processing messages.
An attacker can use this flaw to exhaust resources and perform denial
of service attacks.


For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze5.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your isc-dhcp packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to isc-dhcp announced via advisory DSA 2519-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2519)' (OID: 1.3.6.1.4.1.25623.1.0.71500).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
