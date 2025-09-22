# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53552");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-0392");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 725-1 (ppxp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20725-1");
  script_tag(name:"insight", value:"Jens Steube discovered that ppxp, yet another PPP program, does not
release root privileges when opening potentially user supplied log
files.  This can be tricked into opening a root shell.

For the stable distribution (woody) this problem has been fixed in
version 0.2001080415-6woody1.

For the unstable distribution (sid) this problem has been fixed in
version 0.2001080415-11.");

  script_tag(name:"solution", value:"We recommend that you upgrade your ppxp package.");
  script_tag(name:"summary", value:"The remote host is missing an update to ppxp announced via advisory DSA 725-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-725)' (OID: 1.3.6.1.4.1.25623.1.0.53991).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
