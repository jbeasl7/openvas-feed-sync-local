# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71341");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-0467", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0477", "CVE-2012-0479");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-05-31 11:42:43 -0400 (Thu, 31 May 2012)");
  script_name("Debian Security Advisory DSA 2464-1 (icedove)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202464-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Icedove, an unbranded
version of the Thunderbird mail/news client.

CVE-2012-0467

Bob Clary, Christian Holler, Brian Hackett, Bobby Holley, Gary
Kwong, Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward,
and Olli Pettay discovered memory corruption bugs, which may lead
to the execution of arbitrary code.

CVE-2012-0470

Atte Kettunen discovered that a memory corruption bug in
gfxImageSurface may lead to the execution of arbitrary code.

CVE-2012-0471

Anne van Kesteren discovered that incorrect multibyte octet
decoding may lead to cross-site scripting.

CVE-2012-0477

Masato Kinugawa discovered that incorrect encoding of
Korean and Chinese character sets may lead to cross-site scripting.

CVE-2012-0479

Jeroen van der Gun discovered a spoofing vulnerability in the
presentation of Atom and RSS feeds over HTTPS.

For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze9.

For the unstable distribution (sid), this problem will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your icedove packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to icedove announced via advisory DSA 2464-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2464)' (OID: 1.3.6.1.4.1.25623.1.0.71343).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
