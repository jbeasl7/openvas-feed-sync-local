# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703055");
  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698");
  script_tag(name:"creation_date", value:"2014-10-22 22:00:00 +0000 (Wed, 22 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3055-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3055-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3055");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pidgin' package(s) announced via the DSA-3055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Pidgin, a multi-protocol instant messaging client:

CVE-2014-3694

It was discovered that the SSL/TLS plugins failed to validate the basic constraints extension in intermediate CA certificates.

CVE-2014-3695

Yves Younan and Richard Johnson discovered that emoticons with overly large length values could crash Pidgin.

CVE-2014-3696

Yves Younan and Richard Johnson discovered that malformed Groupwise messages could crash Pidgin.

CVE-2014-3698

Thijs Alkemade and Paul Aurich discovered that malformed XMPP messages could result in memory disclosure.

For the stable distribution (wheezy), these problems have been fixed in version 2.10.10-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 2.10.10-1.

We recommend that you upgrade your pidgin packages.");

  script_tag(name:"affected", value:"'pidgin' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"finch-dev", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-data", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.10.10-1~deb7u1", rls:"DEB7"))) {
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
