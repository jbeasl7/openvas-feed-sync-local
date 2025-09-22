# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703368");
  script_cve_id("CVE-2013-4122");
  script_tag(name:"creation_date", value:"2015-09-24 22:00:00 +0000 (Thu, 24 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3368-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3368-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3368");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-sasl2' package(s) announced via the DSA-3368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that cyrus-sasl2, a library implementing the Simple Authentication and Security Layer, does not properly handle certain invalid password salts. A remote attacker can take advantage of this flaw to cause a denial of service.

For the stable distribution (jessie), this problem has been fixed in version 2.1.26.dfsg1-13+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.1.26.dfsg1-14.

We recommend that you upgrade your cyrus-sasl2 packages.");

  script_tag(name:"affected", value:"'cyrus-sasl2' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-heimdal-dbg", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-mit-dbg", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-db", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.26.dfsg1-13+deb8u1", rls:"DEB8"))) {
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
