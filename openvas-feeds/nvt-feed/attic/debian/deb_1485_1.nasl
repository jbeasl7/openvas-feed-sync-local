# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60362");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1485-1 (icedove)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201485-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail
client, an unbranded version of the Thunderbird client. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0412

Jesse Ruderman, Kai Engert, Martijn Wargers, Mats Palmgren and Paul
Nickerson discovered crashes in the layout engine, which might allow
the execution of arbitrary code.

CVE-2008-0413

Carsten Book, Wesley Garland, Igor Bukanov, moz_bug_r_a4, shutdown,
Philip Taylor and tgirmann discovered crashes in the Javascript
engine, which might allow the execution of arbitrary code.

CVE-2008-0415

moz_bug_r_a4 and Boris Zbarsky discovered discovered several
vulnerabilities in Javascript handling, which could allow
privilege escalation.

CVE-2008-0418

Gerry Eisenhaur and moz_bug_r_a4 discovered that a directory
traversal vulnerability in chrome: URI handling could lead to
information disclosure.

CVE-2008-0419

David Bloom discovered a race condition in the image handling of
designMode elements, which can lead to information disclosure or
potentially the execution of arbitrary code.

CVE-2008-0591

Michal Zalewski discovered that timers protecting security-sensitive
dialogs (which disable dialog elements until a timeout is reached)
could be bypassed by window focus changes through Javascript.

For the stable distribution (etch), these problems have been fixed in
version 1.5.0.13+1.5.0.15b.dfsg1-0etch1.

The Mozilla products in the old stable distribution (sarge) are no
longer supported with security updates.");

  script_tag(name:"solution", value:"We recommend that you upgrade your icedove packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to icedove announced via advisory DSA 1485-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1485)' (OID: 1.3.6.1.4.1.25623.1.0.60575).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
