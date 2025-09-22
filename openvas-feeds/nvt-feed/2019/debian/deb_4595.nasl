# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704595");
  script_cve_id("CVE-2019-3467");
  script_tag(name:"creation_date", value:"2019-12-29 03:00:18 +0000 (Sun, 29 Dec 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-03 14:33:52 +0000 (Fri, 03 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-4595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4595-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4595-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4595");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/debian-lan-config");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'debian-lan-config' package(s) announced via the DSA-4595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that debian-lan-config, a FAI config space for the Debian-LAN system, configured too permissive ACLs for the Kerberos admin server, which allowed password changes for other user principals.

This update provides a fixed configuration for new deployments, for existing setups, the NEWS file shipped in this update provides advice to fix the configuration.

For the oldstable distribution (stretch), this problem has been fixed in version 0.23+deb9u1.

For the stable distribution (buster), this problem has been fixed in version 0.25+deb10u1.

We recommend that you upgrade your debian-lan-config packages.

For the detailed security status of debian-lan-config please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'debian-lan-config' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"debian-lan-config", ver:"0.25+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"debian-lan-config", ver:"0.23+deb9u1", rls:"DEB9"))) {
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
