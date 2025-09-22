# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72408");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2012-2186", "CVE-2012-3812", "CVE-2012-3863", "CVE-2012-4737");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-09-23 02:15:34 -0400 (Sun, 23 Sep 2012)");
  script_name("Debian Security Advisory DSA 2550-1 (asterisk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202550-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Asterisk, a PBX and telephony
toolkit, allowing privilege escalation in the Asterisk Manager, denial of
service or privilege escalation.

For the stable distribution (squeeze), these problems have been fixed in
version 1:1.6.2.9-2+squeeze7.

For the testing distribution (wheezy) and the unstable distribution (sid),
these problems have been fixed in version 1:1.8.13.1~dfsg-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your asterisk packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to asterisk announced via advisory DSA 2550-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2550)' (OID: 1.3.6.1.4.1.25623.1.0.72441).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
