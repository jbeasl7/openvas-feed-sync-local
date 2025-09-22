# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703109");
  script_cve_id("CVE-2014-9323");
  script_tag(name:"creation_date", value:"2014-12-20 23:00:00 +0000 (Sat, 20 Dec 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3109-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3109-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3109");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firebird2.5' package(s) announced via the DSA-3109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dmitry Kovalenko discovered that the Firebird database server is prone to a denial of service vulnerability. An unauthenticated remote attacker could send a malformed network packet to a firebird server, which would cause the server to crash.

For the stable distribution (wheezy), this problem has been fixed in version 2.5.2.26540.ds4-1~deb7u2.

For the upcoming stable distribution (jessie), this problem has been fixed in version 2.5.3.26778.ds4-5.

For the unstable distribution (sid), this problem has been fixed in version 2.5.3.26778.ds4-5.

We recommend that you upgrade your firebird2.5 packages.");

  script_tag(name:"affected", value:"'firebird2.5' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firebird-dev", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic-common", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-classic-dbg", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-common", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-common-doc", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-doc", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-examples", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-server-common", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-super", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-super-dbg", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firebird2.5-superclassic", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbclient2", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbclient2-dbg", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfbembed2.5", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libib-util", ver:"2.5.2.26540.ds4-1~deb7u2", rls:"DEB7"))) {
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
