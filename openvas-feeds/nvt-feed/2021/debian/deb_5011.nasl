# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705011");
  script_cve_id("CVE-2021-21996");
  script_tag(name:"creation_date", value:"2021-11-20 02:00:19 +0000 (Sat, 20 Nov 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-03 15:03:17 +0000 (Thu, 03 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5011-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-5011-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5011");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/salt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'salt' package(s) announced via the DSA-5011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Salt, a powerful remote execution manager, that allow for local privilege escalation on a minion, server side template injection attacks, insufficient checks for eauth credentials, shell and command injections or incorrect validation of SSL certificates.

For the oldstable distribution (buster), this problem has been fixed in version 2018.3.4+dfsg1-6+deb10u3.

For the stable distribution (bullseye), this problem has been fixed in version 3002.6+dfsg1-4+deb11u1.

We recommend that you upgrade your salt packages.

For the detailed security status of salt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'salt' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-doc", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-doc", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
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
