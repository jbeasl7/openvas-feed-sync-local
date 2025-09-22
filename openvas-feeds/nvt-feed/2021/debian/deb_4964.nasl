# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704964");
  script_cve_id("CVE-2021-39365");
  script_tag(name:"creation_date", value:"2021-08-29 01:00:04 +0000 (Sun, 29 Aug 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 18:42:25 +0000 (Mon, 30 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-4964-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-4964-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4964-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4964");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/grilo");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'grilo' package(s) announced via the DSA-4964-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Catanzaro reported a problem in Grilo, a framework for discovering and browsing media. TLS certificate verification is not enabled on the SoupSessionAsync objects created by Grilo, leaving users vulnerable to network MITM attacks.

For the oldstable distribution (buster), this problem has been fixed in version 0.3.7-1+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 0.3.13-1+deb11u1.

We recommend that you upgrade your grilo packages.

For the detailed security status of grilo please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'grilo' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-grilo-0.3", ver:"0.3.7-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-0", ver:"0.3.7-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-bin", ver:"0.3.7-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-dev", ver:"0.3.7-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-doc", ver:"0.3.7-1+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-grilo-0.3", ver:"0.3.13-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-0", ver:"0.3.13-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-bin", ver:"0.3.13-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-dev", ver:"0.3.13-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgrilo-0.3-doc", ver:"0.3.13-1+deb11u1", rls:"DEB11"))) {
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
