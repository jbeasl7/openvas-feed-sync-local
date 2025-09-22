# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703296");
  script_cve_id("CVE-2015-2141");
  script_tag(name:"creation_date", value:"2015-06-28 22:00:00 +0000 (Sun, 28 Jun 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3296-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3296-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3296-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3296");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libcrypto++' package(s) announced via the DSA-3296-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evgeny Sidorov discovered that libcrypto++, a general purpose C++ cryptographic library, did not properly implement blinding to mask private key operations for the Rabin-Williams digital signature algorithm. This could allow remote attackers to mount a timing attack and retrieve the user's private key.

For the oldstable distribution (wheezy), this problem has been fixed in version 5.6.1-6+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 5.6.1-6+deb8u1.

For the testing distribution (stretch), this problem will be fixed in version 5.6.1-7.

For the unstable distribution (sid), this problem has been fixed in version 5.6.1-7.

We recommend that you upgrade your libcrypto++ packages.");

  script_tag(name:"affected", value:"'libcrypto++' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++-dev", ver:"5.6.1-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++-doc", ver:"5.6.1-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++-utils", ver:"5.6.1-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++9", ver:"5.6.1-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++9-dbg", ver:"5.6.1-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++-dev", ver:"5.6.1-6+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++-doc", ver:"5.6.1-6+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++-utils", ver:"5.6.1-6+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++9", ver:"5.6.1-6+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto++9-dbg", ver:"5.6.1-6+deb8u1", rls:"DEB8"))) {
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
