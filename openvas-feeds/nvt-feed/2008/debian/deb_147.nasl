# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53415");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0388");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 147-2 (mailman)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20147-2");
  script_tag(name:"insight", value:"Quoting DSA 147-1:

A cross-site scripting vulnerability was discovered in mailman, a
software to manage electronic mailing lists.  When a properly
crafted URL is accessed with Internet Explorer (other browsers
don't seem to be affected), the resulting webpage is rendered
similar to the real one, but the javascript component is executed
as well, which could be used by an attacker to get access to
sensitive information.  The new version for Debian 2.2 also
includes backports of security related patches from mailman 2.0.11.

This has been fixed in DSA 147-1 already, however, contrary to popular
belief, it turned out that the Python packaging does not upgrade
Python 1.5 users to 2.1 when upgrading from potato to woody.  It also
turned out that the mailman security update unwittingly introduced a
dependency to Python 2.1, both in the security update and upstream,
which left the package unusable on some systems.

This problem has been fixed in version 2.0.11-1woody4 for the current
stable distribution (woody).  Others are not affected.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mailman package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mailman
announced via advisory DSA 147-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mailman", ver:"2.0.11-1woody4", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
