# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58346");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1291-3 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201291-3");
  script_tag(name:"insight", value:"The security update for CVE-2007-2444 introduced a regression in
the handling of the force group share parameter if the forced
group is a local Unix group for domain member servers. This update
fixes this regression.

For the stable distribution (etch), this regression has been fixed in
version 3.0.24-6etch2.

The old stable distribution (sarge) is not affected by this problem.

For the testing and unstable distributions (lenny and sid,
respectively), this regression will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your samba package.");
  script_tag(name:"summary", value:"The remote host is missing an update to samba announced via advisory DSA 1291-3.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1291)' (OID: 1.3.6.1.4.1.25623.1.0.58349).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
