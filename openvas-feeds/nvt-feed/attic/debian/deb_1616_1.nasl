# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61367");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
  script_cve_id("CVE-2008-2713");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 1616-1 (clamav)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201616-1");
  script_tag(name:"insight", value:"Damian Put discovered a vulnerability in the ClamAV anti-virus
toolkit's parsing of Petite-packed Win32 executables.  The weakness
leads to an invalid memory access, and could enable an attacker to
crash clamav by supplying a maliciously crafted Petite-compressed
binary for scanning.  In some configurations, such as when clamav
is used in combination with mail servers, this could cause a system
to fail open, facilitating a follow-on viral attack.

The Common Vulnerabilities and Exposures project identifies this
weakness as CVE-2008-2713.

For the stable distribution (etch), this problem has been fixed in
version 0.90.1dfsg-3etch13.  For the unstable distribution (sid), the
problem has been fixed in version 0.93.1.dfsg-1.1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your clamav packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to clamav announced via advisory DSA 1616-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1616)' (OID: 1.3.6.1.4.1.25623.1.0.61369).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
