# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56011");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-4077", "CVE-2005-3185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 919-1 (curl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 7.13.2-2sarge4.  This update also includes a bugfix against
data corruption.

For the unstable distribution (sid) these problems have been fixed in
version 7.15.1-1.

  We recommend that you upgrade your libcurl packages.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20919-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15756");
  script_tag(name:"summary", value:"The remote host is missing an update to curl announced via advisory DSA 919-1.  Several problems were discovered in libcurl, a multi-protocol file transfer library.  The Common Vulnerabilities and Exposures project identifies the following problems:  CVE-2005-3185  A vulnerability has been discovered a buffer overflow in libcurl that could allow the execution of arbitrary code.  CVE-2005-4077  Stefan Esser discovered several off-by-one errors that allows local users to trigger a buffer overflow and cause a denial of service or bypass PHP security restrictions via certain URLs.  For the old stable distribution (woody) these problems have been fixed in version 7.9.5-1woody1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-919)' (OID: 1.3.6.1.4.1.25623.1.0.56397).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
