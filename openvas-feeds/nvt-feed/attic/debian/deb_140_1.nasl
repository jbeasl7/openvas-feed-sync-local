# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53402");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2012-1586");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 140-1 (libpng2, libpng3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20140-1");
  script_tag(name:"insight", value:"Developers of the PNG library have fixed a buffer overflow in the
progressive reader when the PNG datastream contains more IDAT data
than indicated by the IHDR chunk.  Such deliberately malformed
datastreams would crash applications which could potentially allow an
attacker to execute malicious code.  Programs such as Galeon,
Konquerer and various others make use of these libraries.

To find out which packages depend on this library, you may want to
execute the following commands:

apt-cache showpkg libpng2
apt-cache showpkg libpng3

This problem has been fixed in version 1.0.12-3.woody.1 of libpng and
version 1.2.1-1.1.woody.1 of libpng3 for the current stable
distribution (woody) and in version 1.0.12-4 of libpng and version
1.2.1-2 of libpng3 for the unstable distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your libpng packages immediately and");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng2, libpng3 announced via advisory DSA 140-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-140)' (OID: 1.3.6.1.4.1.25623.1.0.53405).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
