# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54383");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-2231");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 761-1 (heartbeat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 1.2.3-9sarge2.

For the unstable distribution (sid) these problems have been fixed in
version 1.2.3-12.

  We recommend that you upgrade your heartbeat package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20761-1");
  script_tag(name:"summary", value:"The remote host is missing an update to heartbeat announced via advisory DSA 761-1.  Eric Romang discovered several insecure temporary file creations in heartbeat, the subsystem for High-Availability Linux.  For the old stable distribution (woody) these problems have been fixed in version 0.4.9.0l-7.3.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-761)' (OID: 1.3.6.1.4.1.25623.1.0.55052).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
