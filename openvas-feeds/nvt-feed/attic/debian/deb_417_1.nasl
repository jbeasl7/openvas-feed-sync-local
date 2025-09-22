# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53114");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0985");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 417-1 (kernel-patch-2.4.18-powerpc, kernel-image-2.4.18-1-alpha)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20417-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9356");
  script_tag(name:"insight", value:"Paul Starzetz discovered a flaw in bounds checking in mremap() in the
Linux kernel (present in version 2.4.x and 2.6.x) which may allow a
local attacker to gain root privileges.  Version 2.2 is not affected
by this bug.

For the stable distribution (woody) this problem has been fixed in
version 2.4.18-1woody3 for the powerpc architecture.

For the unstable distribution (sid) this problem will be fixed soon
with newly uploaded packages.");

  script_tag(name:"solution", value:"We recommend that you upgrade your kernel packages.  This problem has");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-patch-2.4.18-powerpc, kernel-image-2.4.18-1-alpha announced via advisory DSA 417-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-417)' (OID: 1.3.6.1.4.1.25623.1.0.53118).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
