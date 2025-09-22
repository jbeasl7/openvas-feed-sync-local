# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702836");
  script_cve_id("CVE-2013-6888", "CVE-2013-7325");
  script_tag(name:"creation_date", value:"2014-01-04 23:00:00 +0000 (Sat, 04 Jan 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-06 18:06:01 +0000 (Fri, 06 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-2836-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2836-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2836-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2836");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'devscripts' package(s) announced via the DSA-2836-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in uscan, a tool to scan upstream sites for new releases of packages, which is part of the devscripts package. An attacker controlling a website from which uscan would attempt to download a source tarball could execute arbitrary code with the privileges of the user running uscan.

The Common Vulnerabilities and Exposures project id CVE-2013-6888 has been assigned to identify them.

For the stable distribution (wheezy), these problems have been fixed in version 2.12.6+deb7u2.

For the testing distribution (jessie) and the unstable distribution (sid), these problems have been fixed in version 2.13.9.

We recommend that you upgrade your devscripts packages.");

  script_tag(name:"affected", value:"'devscripts' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"devscripts", ver:"2.12.6+deb7u2", rls:"DEB7"))) {
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
