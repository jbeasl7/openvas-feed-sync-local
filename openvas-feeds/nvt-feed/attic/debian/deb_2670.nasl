# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71349");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3122", "CVE-2011-3125", "CVE-2011-3126", "CVE-2011-3127", "CVE-2011-3128", "CVE-2011-3129", "CVE-2011-3130", "CVE-2011-4956", "CVE-2011-4957", "CVE-2012-2399", "CVE-2012-2400", "CVE-2012-2401", "CVE-2012-2402", "CVE-2012-2403", "CVE-2012-2404");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-31 11:44:38 -0400 (Thu, 31 May 2012)");
  script_name("Debian Security Advisory DSA 2670-1 (wordpress)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202670-1");
  script_tag(name:"insight", value:"Several vulnerabilities were identified in Wordpress, a web blogging
tool.  As the CVEs were allocated from releases announcements and
specific fixes are usually not identified, it has been decided to
upgrade the Wordpress package to the latest upstream version instead
of backporting the patches.

This means extra care should be taken when upgrading, especially when
using third-party plugins or themes, since compatibility may have been
impacted along the way.  We recommend that users check their install
before doing the upgrade.

For the stable distribution (squeeze), those problems have been fixed in
version 3.3.2+dfsg-1~squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), those problems have been fixed in version 3.3.2+dfsg-1.

This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-2670)' (OID: 1.3.6.1.4.1.25623.1.0.702670).");

  script_tag(name:"solution", value:"We recommend that you upgrade your wordpress packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to wordpress
announced via advisory DSA 2670-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
