# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55728");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-2958");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 871-1 (libgda2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 1.2.1-2sarge1.

For the unstable distribution (sid) these problems will be fixed soon.

  We recommend that you upgrade your libgda2 packages.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20871-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15200");
  script_tag(name:"summary", value:"The remote host is missing an update to libgda2 announced via advisory DSA 871-1.  Steve Kemp discovered two format string vulnerabilities in libgda2, the GNOME Data Access library for GNOME2, which may lead to the execution of arbitrary code in programs that use this library.  The old stable distribution (woody) is not affected by these problems.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-871)' (OID: 1.3.6.1.4.1.25623.1.0.55746).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
