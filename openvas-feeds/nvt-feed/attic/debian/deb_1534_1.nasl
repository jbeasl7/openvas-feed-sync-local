# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60655");
  script_cve_id("CVE-2007-4879", "CVE-2007-6589", "CVE-2008-0420", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_tag(name:"creation_date", value:"2008-04-07 18:38:54 +0000 (Mon, 07 Apr 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1534-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1534-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1534");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-1534-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1534)' (OID: 1.3.6.1.4.1.25623.1.0.60862).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceape internet suite, an unbranded version of the Seamonkey Internet Suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-4879

Peter Brodersen and Alexander Klink discovered that the autoselection of SSL client certificates could lead to users being tracked, resulting in a loss of privacy.

CVE-2008-1233

moz_bug_r_a4 discovered that variants of CVE-2007-3738 and CVE-2007-5338 allow the execution of arbitrary code through XPCNativeWrapper.

CVE-2008-1234

moz_bug_r_a4 discovered that insecure handling of event handlers could lead to cross-site scripting.

CVE-2008-1235

Boris Zbarsky, Johnny Stenback and moz_bug_r_a4 discovered that incorrect principal handling could lead to cross-site scripting and the execution of arbitrary code.

CVE-2008-1236

Tom Ferris, Seth Spitzer, Martin Wargers, John Daggett and Mats Palmgren discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2008-1237

georgi, tgirmann and Igor Bukanov discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2008-1238

Gregory Fleischer discovered that HTTP Referrer headers were handled incorrectly in combination with URLs containing Basic Authentication credentials with empty usernames, resulting in potential Cross-Site Request Forgery attacks.

CVE-2008-1240

Gregory Fleischer discovered that web content fetched through the jar: protocol can use Java to connect to arbitrary ports. This is only an issue in combination with the non-free Java plugin.

CVE-2008-1241

Chris Thomas discovered that background tabs could generate XUL popups overlaying the current tab, resulting in potential spoofing attacks.

The Mozilla products from the old stable distribution (sarge) are no longer supported.

For the stable distribution (etch), these problems have been fixed in version 1.0.13~pre080323b-0etch1.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
