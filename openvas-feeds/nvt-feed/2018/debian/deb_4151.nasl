# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704151");
  script_cve_id("CVE-2018-1000140");
  script_tag(name:"creation_date", value:"2018-03-25 22:00:00 +0000 (Sun, 25 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 13:23:59 +0000 (Fri, 20 Apr 2018)");

  script_name("Debian: Security Advisory (DSA-4151-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4151-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4151-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4151");
  script_xref(name:"URL", value:"https://www.rsyslog.com/cve-2018-1000140/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/librelp");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'librelp' package(s) announced via the DSA-4151-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bas van Schaik and Kevin Backhouse discovered a stack-based buffer overflow vulnerability in librelp, a library providing reliable event logging over the network, triggered while checking x509 certificates from a peer. A remote attacker able to connect to rsyslog can take advantage of this flaw for remote code execution by sending a specially crafted x509 certificate.

Details can be found in the upstream advisory: [link moved to references]

For the oldstable distribution (jessie), this problem has been fixed in version 1.2.7-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 1.2.12-1+deb9u1.

We recommend that you upgrade your librelp packages.

For the detailed security status of librelp please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'librelp' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"librelp-dev", ver:"1.2.7-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librelp0", ver:"1.2.7-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"librelp-dev", ver:"1.2.12-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librelp0", ver:"1.2.12-1+deb9u1", rls:"DEB9"))) {
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
