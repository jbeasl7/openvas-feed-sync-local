# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60936");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-05-27 15:44:50 +0200 (Tue, 27 May 2008)");
  script_cve_id("CVE-2008-0783", "CVE-2008-0785");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1569-2 (cacti)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201569-2");
  script_tag(name:"insight", value:"The original update for cacti unfortunately introduced a regression.
Updated packages have been created to address this. For reference, the
full advisory text is quoted below.

It was discovered that Cacti, a systems and services monitoring frontend,
performed insufficient input sanitising, leading to cross site scripting
and SQL injection being possible.

For the stable distribution (etch), this problem has been fixed in
version 0.8.6i-3.4.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.7b-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your cacti package.");
  script_tag(name:"summary", value:"The remote host is missing an update to cacti announced via advisory DSA 1569-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1569)' (OID: 1.3.6.1.4.1.25623.1.0.61359).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
