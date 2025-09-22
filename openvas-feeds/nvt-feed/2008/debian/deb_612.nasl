# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53717");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-1170");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 612-1 (a2ps)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20612-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11025");
  script_tag(name:"insight", value:"Rudolf Polzer discovered a vulnerability in a2ps, a converter and
pretty-printer for many formats to PostScript.  The program did not
escape shell meta characters properly which could lead to the
execution of arbitrary commands as a privileged user if a2ps is
installed as a printer filter.

For the stable distribution (woody) this problem has been fixed in
version 4.13b-16woody1

For the unstable distribution (sid) this problem has been fixed in
version 4.13b-4.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your a2ps package.");
  script_tag(name:"summary", value:"The remote host is missing an update to a2ps
announced via advisory DSA 612-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"a2ps", ver:"4.13b-16woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
