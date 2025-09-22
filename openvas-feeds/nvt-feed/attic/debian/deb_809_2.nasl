# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55494");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-2794");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 809-2 (squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 2.5.9-10sarge1.

For the unstable distribution (sid) this problem has been fixed in
version 2.5.10-5.

  We recommend that you upgrade your squid package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20809-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14761");
  script_tag(name:"summary", value:"The remote host is missing an update to squid announced via advisory DSA 809-2.  Certain aborted requests that trigger an assertion in squid, the popular WWW proxy cache, may allow remote attackers to cause a denial of service.  This update also fixes a regression caused by DSA 751.  For the oldstable distribution (woody) this problem has been fixed in version 2.4.6-2woody10.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-809)' (OID: 1.3.6.1.4.1.25623.1.0.55816).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
