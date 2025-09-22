# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53556");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-1151", "CVE-2005-1152");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 728-1 (qpopper)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20728-1");
  script_tag(name:"insight", value:"Two bugs have been discovered in qpopper, an enhanced Post Office
Protocol (POP3) server.  The Common Vulnerability and Exposures
project identifies the following problems:

CVE-2005-1151

Jens Steube discovered that while processing local files owned or
provided by a normal user privileges weren't dropped, which could
lead to the overwriting or creation of arbitrary files as root.

CVE-2005-1152

The upstream developers noticed that qpopper could be tricked to
creating group- or world-writable files.

For the stable distribution (woody) these problems have been fixed in
version 4.0.4-2.woody.5.

For the testing distribution (sarge) these problems have been fixed in
version 4.0.5-4sarge1.

For the unstable distribution (sid) these problems will be fixed in
version 4.0.5-4sarge1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your qpopper package.");
  script_tag(name:"summary", value:"The remote host is missing an update to qpopper announced via advisory DSA 728-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-728)' (OID: 1.3.6.1.4.1.25623.1.0.53557).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
