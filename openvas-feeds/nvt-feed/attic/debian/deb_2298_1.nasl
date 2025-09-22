# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70233");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-1452", "CVE-2011-3192");
  script_name("Debian Security Advisory DSA 2298-1 (apache2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202298-1");
  script_tag(name:"insight", value:"Two issues have been found in the Apache HTTPD web server:

CVE-2011-3192

A vulnerability has been found in the way the multiple overlapping
ranges are handled by the Apache HTTPD server. This vulnerability
allows an attacker to cause Apache HTTPD to use an excessive amount of
memory, causing a denial of service.

CVE-2010-1452

A vulnerability has been found in mod_dav that allows an attacker to
cause a daemon crash, causing a denial of service. This issue only
affects the Debian 5.0 oldstable/lenny distribution.


For the oldstable distribution (lenny), these problems have been fixed
in version 2.2.9-10+lenny10.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.16-6+squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.2.19-2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your apache2 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to apache2 announced via advisory DSA 2298-1.

  This VT has been deprecated and merged into the VT 'deb_2298.nasl' (OID: 1.3.6.1.4.1.25623.1.0.70233).]");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
