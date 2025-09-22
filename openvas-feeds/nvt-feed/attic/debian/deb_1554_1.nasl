# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60858");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-04-30 19:28:13 +0200 (Wed, 30 Apr 2008)");
  script_cve_id("CVE-2008-1474");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 1554-1 (roundup)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201554-1");
  script_tag(name:"insight", value:"Roundup, an issue tracking system, fails to properly escape HTML input,
allowing an attacker to inject client-side code (typically JavaScript)
into a document that may be viewed in the victim's browser.

For the stable distribution (etch), this problem has been fixed in version
1.2.1-5+etch1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your roundup packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to roundup announced via advisory DSA 1554-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1554)' (OID: 1.3.6.1.4.1.25623.1.0.60937).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
