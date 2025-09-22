# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53408");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 18:38:00 +0000 (Thu, 08 Feb 2024)");
  script_name("Debian Security Advisory DSA 146-2 (dietlibc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20146-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5356");
  script_tag(name:"insight", value:"The upstream author of dietlibc, Felix von Leitner, discovered a
potential division by zero chance in the fwrite and calloc integer
overflow checks, which are fixed in the version below.

The new version includes fixes from DSA 146-1.  For completeness we
enclose the text of the other advisory:

An integer overflow bug has been discovered in the RPC library
used by dietlibc, a libc optimized for small size, which is
derived from the SunRPC library.  This bug could be exploited to
gain unauthorized root access to software linking to this code.
The packages below also fix integer overflows in the calloc, fread
and fwrite code.  They are also more strict regarding hostile DNS
packets that could lead to a vulnerability otherwise.

This problem has been fixed in version 0.12-2.4 for the current stable
distribution (woody) and in version 0.20-0cvs20020808 for the unstable
distribution (sid).  Debian 2.2 (potato) is not affected since it
doesn't contain dietlibc packages.");

  script_tag(name:"solution", value:"We recommend that you upgrade your dietlibc packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to dietlibc
announced via advisory DSA 146-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dietlibc-doc", ver:"0.12-2.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dietlibc-dev", ver:"0.12-2.4", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
