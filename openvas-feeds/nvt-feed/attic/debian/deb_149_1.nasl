# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53413");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 18:38:00 +0000 (Thu, 08 Feb 2024)");
  script_name("Debian Security Advisory DSA 149-1 (glibc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20149-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5356");
  script_tag(name:"insight", value:"An integer overflow bug has been discovered in the RPC library used by
GNU libc, which is derived from the SunRPC library.  This bug could be
exploited to gain unauthorized root access to software linking to this
code.  The packages below also fix integer overflows in the malloc
code.  They also contain a fix from Andreas Schwab to reduce
linebuflen in parallel to bumping up the buffer pointer in the NSS DNS
code.

This problem has been fixed in version 2.1.3-23 for the old stable
distribution (potato), in version 2.2.5-11.1 for the current stable
distribution (woody) and in version 2.2.5-13 for the unstable
distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your libc6 packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to glibc announced via advisory DSA 149-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-149)' (OID: 1.3.6.1.4.1.25623.1.0.53423).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
