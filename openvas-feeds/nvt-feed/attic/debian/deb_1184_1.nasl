# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57408");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-2660", "CVE-2005-4798", "CVE-2006-1052", "CVE-2006-1343", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3745", "CVE-2006-4093", "CVE-2006-4145", "CVE-2006-4535");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Debian Security Advisory DSA 1184-1 (kernel-source-2.6.8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-source-2.6.8 announced via advisory DSA 1184-1. For details, please visit the referenced security advisories.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1184)' (OID: 1.3.6.1.4.1.25623.1.0.57477).");
  script_tag(name:"solution", value:"The following matrix explains which kernel version for which
architecture fixes the problem mentioned above:

stable (sarge)
Source                           2.6.8-16sarge5
Alpha architecture               2.6.8-16sarge5
AMD64 architecture               2.6.8-16sarge5
HP Precision architecture        2.6.8-6sarge5
Intel IA-32 architecture         2.6.8-16sarge5
Intel IA-64 architecture         2.6.8-14sarge5
Motorola 680x0 architecture      2.6.8-4sarge5
PowerPC architecture             2.6.8-12sarge5
IBM S/390                        2.6.8-5sarge5
Sun Sparc architecture           2.6.8-15sarge5
FAI                              1.9.1sarge4

For the unstable distribution (sid) these problems have been fixed in
version 2.6.18-1.

  We recommend that you upgrade your kernel package and reboot.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201184-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18099");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18105");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19396");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
