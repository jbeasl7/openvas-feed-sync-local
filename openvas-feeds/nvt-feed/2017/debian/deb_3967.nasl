# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703967");
  script_cve_id("CVE-2017-14032");
  script_tag(name:"creation_date", value:"2017-09-07 22:00:00 +0000 (Thu, 07 Sep 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-12 16:06:02 +0000 (Tue, 12 Sep 2017)");

  script_name("Debian: Security Advisory (DSA-3967-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-3967-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3967-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3967");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mbedtls' package(s) announced via the DSA-3967-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An authentication bypass vulnerability was discovered in mbed TLS, a lightweight crypto and SSL/TLS library, when the authentication mode is configured as optional. A remote attacker can take advantage of this flaw to mount a man-in-the-middle attack and impersonate an intended peer via an X.509 certificate chain with many intermediates.

For the stable distribution (stretch), this problem has been fixed in version 2.4.2-1+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 2.6.0-1.

For the unstable distribution (sid), this problem has been fixed in version 2.6.0-1.

We recommend that you upgrade your mbedtls packages.");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libmbedcrypto0", ver:"2.4.2-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-dev", ver:"2.4.2-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-doc", ver:"2.4.2-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls10", ver:"2.4.2-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedx509-0", ver:"2.4.2-1+deb9u1", rls:"DEB9"))) {
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
