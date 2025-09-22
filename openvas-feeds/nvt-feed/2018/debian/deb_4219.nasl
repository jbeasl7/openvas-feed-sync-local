# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704219");
  script_cve_id("CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079");
  script_tag(name:"creation_date", value:"2018-06-07 22:00:00 +0000 (Thu, 07 Jun 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 21:30:37 +0000 (Thu, 05 Apr 2018)");

  script_name("Debian: Security Advisory (DSA-4219-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4219-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4219-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4219");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jruby");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jruby' package(s) announced via the DSA-4219-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in jruby, a Java implementation of the Ruby programming language. They would allow an attacker to use specially crafted gem files to mount cross-site scripting attacks, cause denial of service through an infinite loop, write arbitrary files, or run malicious code.

For the stable distribution (stretch), these problems have been fixed in version 1.7.26-1+deb9u1.

We recommend that you upgrade your jruby packages.

In addition, this message serves as an announcement that security support for jruby in the Debian 8 oldstable release (jessie) is now discontinued.

Users of jruby in Debian 8 that want security updates are strongly encouraged to upgrade now to the current Debian 9 stable release (stretch).

For the detailed security status of jruby please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'jruby' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"jruby", ver:"1.7.26-1+deb9u1", rls:"DEB9"))) {
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
