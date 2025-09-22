# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55899");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-2475");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 903-1 (unzip)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 5.52-1sarge2.

For the unstable distribution (sid) this problem has been fixed in
version 5.52-4.

  We recommend that you upgrade your unzip package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20903-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14450");
  script_tag(name:"summary", value:"The remote host is missing an update to unzip announced via advisory DSA 903-1.  Imran Ghory discovered a race condition in the permissions setting code in unzip.  When decompressing a file in a directory an attacker has access to, unzip could be tricked to set the file permissions to a different file the user has permissions to.  For the old stable distribution (woody) this problem has been fixed in version 5.50-1woody4.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-903)' (OID: 1.3.6.1.4.1.25623.1.0.56143).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
