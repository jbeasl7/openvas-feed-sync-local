# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56191");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-0162");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 947-1 (clamav)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 0.84-2.sarge.7.

For the unstable distribution (sid) this problem has been fixed in
version 0.86.2-1.

  We recommend that you upgrade your clamav package immediately.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20947-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16191");
  script_tag(name:"summary", value:"The remote host is missing an update to clamav announced via advisory DSA 947-1.  A heap overflow has been discovered in ClamAV, a virus scanner, which could allow an attacker to execute arbitrary code by sending a carefully crafted UPX-encoded executable to a system running ClamAV. In addition, other potential overflows have been corrected.  The old stable distribution (woody) does not include ClamAV.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-947)' (OID: 1.3.6.1.4.1.25623.1.0.56207).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
