# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60793");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
  script_cve_id("CVE-2008-1531");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 1540-2 (lighttpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201540-2");
  script_tag(name:"insight", value:"It was discovered that lighttpd, a fast webserver with minimal memory
footprint, was didn't correctly handle SSL errors.  This could allow
a remote attacker to disconnect all active SSL connections.

This security update fixes a regression in the previous one, which caused
SSL failures.

For the stable distribution (etch), this problem has been fixed in version
1.4.13-4etch8.");

  script_tag(name:"solution", value:"We recommend that you upgrade your lighttpd package.");
  script_tag(name:"summary", value:"The remote host is missing an update to lighttpd announced via advisory DSA 1540-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1540)' (OID: 1.3.6.1.4.1.25623.1.0.61364).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
