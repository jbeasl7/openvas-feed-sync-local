# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70703");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1644", "CVE-2010-1645", "CVE-2010-2543", "CVE-2010-2545", "CVE-2011-4824");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-02-11 03:26:57 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2384-1 (cacti)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202384-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in cacti, a graphing tool
for monitoring data. Multiple cross site scripting issues allow remote
attackers to inject arbitrary web script or HTML. An SQL injection
vulnerability allows remote attackers to execute arbitrary SQL commands.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.8.7b-2.1+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.7g-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7i-2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your cacti packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to cacti announced via advisory DSA 2384-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2384)' (OID: 1.3.6.1.4.1.25623.1.0.70722).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
