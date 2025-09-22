# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56408");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-0042");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 1000-1 (libapreq2-perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 2.04-dev-1sarge1.

For the unstable distribution (sid) this problem has been fixed in
version 2.07-1.

  We recommend that you upgrade your libapreq2, libapache2-mod-apreq2.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201000-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16710");
  script_tag(name:"summary", value:"The remote host is missing an update to libapreq2-perl announced via advisory DSA 1000-1.  An algorithm weakness has been discovered in Apache2::Request, the generic request library for Apache2 which can be exploited remotely and cause a denial of service via CPU consumption.  The old stable distribution (woody) does not contain this package.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1000)' (OID: 1.3.6.1.4.1.25623.1.0.56527).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
