# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53530");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-1154");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 701-1 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20701-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11973");
  script_tag(name:"insight", value:"Greg MacManus discovered an integer overflow in the smb daemon from
Samba, a LanManager like file and printer server for GNU/Linux and
Unix-like systems.  Requesting a very large number of access control
descriptors from the server could exploit the integer overflow, which
may result in a buffer overflow which could lead to the execution of
arbitrary code with root privileges.  Upstream developers have
discovered more possible integer overflows that are fixed with this
update as well.

For the stable distribution (woody) these problems have been fixed in
version 2.2.3a-14.2.

For the unstable distribution (sid) these problems have been fixed in
version 3.0.10-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to samba announced via advisory DSA 701-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-701)' (OID: 1.3.6.1.4.1.25623.1.0.53540).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
