# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53597");
  script_version("2023-07-19T05:05:15+0000");
  script_cve_id("CVE-2003-0308");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 305-1 (sendmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|2\.2)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20305-1");
  script_tag(name:"insight", value:"Paul Szabo discovered bugs in three scripts included in the sendmail
package where temporary files were created insecurely (expn,
checksendmail and doublebounce.pl).  These bugs could allow an
attacker to gain the privileges of a user invoking the script
(including root).

For the stable distribution (woody) these problems have been fixed in
version 8.12.3-6.4.

For the old stable distribution (potato) these problems have been fixed
in version 8.9.3-26.1.

For the unstable distribution (sid) these problems have been fixed in
version 8.12.9-2.

We recommend that you update your sendmail package.");
  script_tag(name:"summary", value:"The remote host is missing an update to sendmail
announced via advisory DSA 305-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"sendmail-doc", ver:"8.12.3-6.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmilter-dev", ver:"8.12.3-6.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sendmail", ver:"8.12.3-6.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sendmail", ver:"8.9.3-26.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
