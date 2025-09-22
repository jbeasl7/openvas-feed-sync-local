# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66591");
  script_cve_id("CVE-2007-2383", "CVE-2008-3903", "CVE-2008-7220", "CVE-2009-0041", "CVE-2009-3727", "CVE-2009-4055");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1952-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1952-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1952");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-1952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in asterisk, an Open Source PBX and telephony toolkit. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0041

It is possible to determine valid login names via probing, due to the IAX2 response from asterisk (AST-2009-001).

CVE-2008-3903

It is possible to determine a valid SIP username, when Digest authentication and authalwaysreject are enabled (AST-2009-003).

CVE-2009-3727

It is possible to determine a valid SIP username via multiple crafted REGISTER messages (AST-2009-008).

CVE-2008-7220 CVE-2007-2383 It was discovered that asterisk contains an obsolete copy of the Prototype JavaScript framework, which is vulnerable to several security issues. This copy is unused and now removed from asterisk (AST-2009-009).

CVE-2009-4055

It was discovered that it is possible to perform a denial of service attack via RTP comfort noise payload with a long data length (AST-2009-010).

The current version in oldstable is not supported by upstream anymore and is affected by several security issues. Backporting fixes for these and any future issues has become unfeasible and therefore we need to drop our security support for the version in oldstable. We recommend that all asterisk users upgrade to the stable distribution (lenny).

For the stable distribution (lenny), these problems have been fixed in version 1:1.4.21.2~dfsg-3+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 1:1.6.2.0~rc7-1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.4.21.2~dfsg-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
