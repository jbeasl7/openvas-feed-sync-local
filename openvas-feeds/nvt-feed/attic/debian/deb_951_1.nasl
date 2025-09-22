# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56214");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-4065", "CVE-2005-4644");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 951-1 (trac)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 0.8.1-3sarge3.

For the unstable distribution (sid) these problems have been fixed in
version 0.9.3-1.

  We recommend that you upgrade your trac package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20951-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16198");
  script_tag(name:"summary", value:"The remote host is missing an update to trac announced via advisory DSA 951-1.  Several vulnerabilities have been discovered in trac, an enhanced wiki and issue tracking system for software development projects.  The Common Vulnerabilities and Exposures project identifie the following problems:  CVE-2005-4065  Due to missing input sanitising it is possible to inject arbitrary SQL code into the SQL statements.  CVE-2005-4644  A cross-site scripting vulnerability has been discovered that allows remote attackers to inject arbitrary web script or HTML.  The old stable distribution (woody) does not contain trac packages.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-951)' (OID: 1.3.6.1.4.1.25623.1.0.56215).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
