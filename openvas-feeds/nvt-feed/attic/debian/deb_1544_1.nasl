# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60790");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
  script_cve_id("CVE-2008-1637");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1544-1 (pdns-recursor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201544-1");
  script_tag(name:"insight", value:"Amit Klein discovered that pdns-recursor, a caching DNS resolver, uses a
weak random number generator to create DNS transaction IDs and UDP
source port numbers.  As a result, cache poisoning attacks were
simplified. (CVE-2008-1637)

For the stable distribution (etch), these problems have been fixed in
version 3.1.4-1+etch1.

For the unstable distribution (sid), these problems have been fixed in
version 3.1.5-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your pdns-recursor package.");
  script_tag(name:"summary", value:"The remote host is missing an update to pdns-recursor announced via advisory DSA 1544-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1544)' (OID: 1.3.6.1.4.1.25623.1.0.61360).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
