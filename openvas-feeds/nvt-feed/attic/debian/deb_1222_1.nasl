# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57683");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1222-1 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in version
1.2.10-15sarge3.

For the unstable distribution (sid) these problems have been fixed in
version 1.3.0-16 of the proftpd-dfsg package.

  We recommend that you upgrade your proftpd package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201222-1");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd announced via advisory DSA 1222-1.  Several remote vulnerabilities have been discovered in the proftpd FTP daemon, which may lead to the execution of arbitrary code or denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:  CVE-2006-5815  It was discovered that a buffer overflow in the sreplace() function may lead to denial of service and possibly the execution of arbitrary code.  CVE-2006-6170  It was discovered that a buffer overflow in the mod_tls addon module may lead to the execution of arbitrary code.  CVE-2006-6171  It was discovered that insufficient validation of FTP command buffer size limits may lead to denial of service. Due to unclear information this issue was already fixed in DSA-1218 as CVE-2006-5815.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1222)' (OID: 1.3.6.1.4.1.25623.1.0.57686).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
