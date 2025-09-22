# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53128");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 429-1 (gnupg)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20429-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9115");
  script_tag(name:"insight", value:"Phong Nguyen identified a severe bug in the way GnuPG creates and uses
ElGamal keys for signing.  This is a significant security failure
which can lead to a compromise of almost all ElGamal keys used for
signing.

This update disables the use of this type of key.

For the current stable distribution (woody) this problem has been
fixed in version 1.0.6-4woody1.

For the unstable distribution, this problem has been fixed in version
1.2.4-1.

We recommend that you update your gnupg package.");
  script_tag(name:"summary", value:"The remote host is missing an update to gnupg announced via advisory DSA 429-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-429)' (OID: 1.3.6.1.4.1.25623.1.0.53137).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
