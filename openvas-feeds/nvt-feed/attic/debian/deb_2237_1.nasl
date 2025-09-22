# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69734");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-0419");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 2237-1 (apr)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202237-1");
  script_tag(name:"insight", value:"A flaw was found in the APR library, which could be exploited through
Apache HTTPD's mod_autoindex.  If a directory indexed by mod_autoindex
contained files with sufficiently long names, a remote attacker could
send a carefully crafted request which would cause excessive CPU
usage. This could be used in a denial of service attack.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.12-5+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.2-6+squeeze1.

For the testing distribution (wheezy), this problem will be fixed in
version 1.4.4-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.4-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your apr packages and restart the");
  script_tag(name:"summary", value:"The remote host is missing an update to apr announced via advisory DSA 2237-1.

  This VT has been deprecated and merged into the VT 'deb_2237.nasl' (OID: 1.3.6.1.4.1.25623.1.0.69734).]");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
