# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703829");
  script_cve_id("CVE-2015-6644");
  script_tag(name:"creation_date", value:"2017-04-10 22:00:00 +0000 (Mon, 10 Apr 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-07 14:59:35 +0000 (Thu, 07 Jan 2016)");

  script_name("Debian: Security Advisory (DSA-3829-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3829-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3829-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3829");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bouncycastle' package(s) announced via the DSA-3829-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Quan Nguyen discovered that a missing boundary check in the Galois/Counter mode implementation of Bouncy Castle (a Java implementation of cryptographic algorithms) may result in information disclosure.

For the stable distribution (jessie), this problem has been fixed in version 1.49+dfsg-3+deb8u2.

For the upcoming stable distribution (stretch), this problem has been fixed in version 1.54-1.

For the unstable distribution (sid), this problem has been fixed in version 1.54-1.

We recommend that you upgrade your bouncycastle packages.");

  script_tag(name:"affected", value:"'bouncycastle' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcmail-java-doc", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpg-java-doc", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpkix-java", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcpkix-java-doc", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbcprov-java-doc", ver:"1.49+dfsg-3+deb8u2", rls:"DEB8"))) {
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
