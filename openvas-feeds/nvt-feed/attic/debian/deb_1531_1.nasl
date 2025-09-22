# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60652");
  script_cve_id("CVE-2008-1569");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-04-07 20:38:54 +0200 (Mon, 07 Apr 2008)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Debian Security Advisory DSA 1531-1 (policyd-weight)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201531-1");
  script_tag(name:"insight", value:"Chris Howells discovered that policyd-weight, a policy daemon for the Postfix
mail transport agent, created its socket in an insecure way, which may be
exploited to overwrite or remove arbitrary files from the local system.

For the stable distribution (etch), this problem has been fixed in version
0.1.14-beta-6etch1.

The old stable distribution (sarge) does not contain a policyd-weight package.

For the unstable distribution (sid), this problem will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your policyd-weight package.");
  script_tag(name:"summary", value:"The remote host is missing an update to policyd-weight announced via advisory DSA 1531-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1531)' (OID: 1.3.6.1.4.1.25623.1.0.60656).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
