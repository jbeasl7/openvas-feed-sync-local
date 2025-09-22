# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704259");
  script_cve_id("CVE-2017-17405", "CVE-2017-17742", "CVE-2017-17790", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_tag(name:"creation_date", value:"2018-07-30 22:00:00 +0000 (Mon, 30 Jul 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 21:30:37 +0000 (Thu, 05 Apr 2018)");

  script_name("Debian: Security Advisory (DSA-4259-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4259-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4259-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4259");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby2.3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.3' package(s) announced via the DSA-4259-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language, which may result in incorrect processing of HTTP/FTP, directory traversal, command injection, unintended socket creation or information disclosure.

This update also fixes several issues in RubyGems which could allow an attacker to use specially crafted gem files to mount cross-site scripting attacks, cause denial of service through an infinite loop, write arbitrary files, or run malicious code.

For the stable distribution (stretch), these problems have been fixed in version 2.3.3-1+deb9u3.

We recommend that you upgrade your ruby2.3 packages.

For the detailed security status of ruby2.3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby2.3' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-dev", ver:"2.3.3-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-doc", ver:"2.3.3-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-tcltk", ver:"2.3.3-1+deb9u3", rls:"DEB9"))) {
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
