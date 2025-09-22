# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53756");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0838");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 182-1 (kdegraphics)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20182-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5808");
  script_tag(name:"insight", value:"Zen-parse discovered a buffer overflow in gv, a PostScript and PDF
viewer for X11.  The same code is present in kghostview which is part
of the KDE-Graphics package.  This problem is triggered by scanning
the PostScript file and can be exploited by an attacker sending a
malformed PostScript or PDF file.  The attacker is able to cause
arbitrary code to be run with the privileges of the victim.

This problem has been fixed in version 2.2.2-6.8 for the current
stable distribution (woody) and in version 2.2.2-6.9 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since no KDE is included.");

  script_tag(name:"solution", value:"We recommend that you upgrade your kghostview package.");
  script_tag(name:"summary", value:"The remote host is missing an update to kdegraphics
announced via advisory DSA 182-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kghostview", ver:"2.2.2-6.8", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
