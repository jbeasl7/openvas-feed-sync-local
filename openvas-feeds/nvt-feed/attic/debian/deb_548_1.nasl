# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53238");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0817");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 548-1 (imlib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20548-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11084");
  script_tag(name:"insight", value:"Marcus Meissner discovered a heap overflow error in imlib, an imaging
library for X and X11, that could be abused by an attacker to execute
arbitrary code on the vicims machine.

For the stable distribution (woody) this problem has been fixed in
version 1.9.14-2wody1.

For the unstable distribution (sid) this problem has been fixed in
version 1.9.14-17 of imlib and in version 1.9.14-16 of imlib+png2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your imlib1 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to imlib announced via advisory DSA 548-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-548)' (OID: 1.3.6.1.4.1.25623.1.0.55747).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
