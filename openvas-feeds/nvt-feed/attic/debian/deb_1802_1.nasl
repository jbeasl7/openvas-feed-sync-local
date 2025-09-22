# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64033");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1802-1 (squirrelmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201802-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in SquirrelMail,
a webmail application. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2009-1578

Cross site scripting was possible through a number of pages which
allowed an attacker to steal sensitive session data.

CVE-2009-1579

Code injection was possible when SquirrelMail was configured to
use the map_yp_alias function to authenticate users. This is not
the default.

CVE-2009-1580

It was possible to hijack an active user session by planting a
specially crafted cookie into the user's browser.

CVE-2009-1581

Specially crafted HTML emails could use the CSS positioning feature
to place email content over the SquirrelMail user interface, allowing
for phishing.

For the old stable distribution (etch), these problems have been fixed in
version 1.4.9a-4.

For the stable distribution (lenny), these problems have been fixed in
version 1.4.15-4+lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.18-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your squirrelmail package.");
  script_tag(name:"summary", value:"The remote host is missing an update to squirrelmail announced via advisory DSA 1802-1.

  This VT has been deprecated and merged into the VT 'deb_1802.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64033).]");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
