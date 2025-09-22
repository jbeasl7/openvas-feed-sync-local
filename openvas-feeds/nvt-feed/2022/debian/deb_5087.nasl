# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705087");
  script_cve_id("CVE-2022-24407");
  script_tag(name:"creation_date", value:"2022-03-02 02:00:07 +0000 (Wed, 02 Mar 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 19:08:42 +0000 (Thu, 03 Mar 2022)");

  script_name("Debian: Security Advisory (DSA-5087-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5087-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5087-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5087");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cyrus-sasl2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-sasl2' package(s) announced via the DSA-5087-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SQL plugin in cyrus-sasl2, a library implementing the Simple Authentication and Security Layer, is prone to a SQL injection attack. An authenticated remote attacker can take advantage of this flaw to execute arbitrary SQL commands and for privilege escalation.

For the oldstable distribution (buster), this problem has been fixed in version 2.1.27+dfsg-1+deb10u2.

For the stable distribution (bullseye), this problem has been fixed in version 2.1.27+dfsg-2.1+deb11u1.

We recommend that you upgrade your cyrus-sasl2 packages.

For the detailed security status of cyrus-sasl2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cyrus-sasl2' package(s) on Debian 10, Debian 11.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-db", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.27+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-db", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.27+dfsg-2.1+deb11u1", rls:"DEB11"))) {
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
