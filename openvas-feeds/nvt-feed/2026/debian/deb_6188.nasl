# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6188");
  script_cve_id("CVE-2026-28384", "CVE-2026-33542", "CVE-2026-33897");
  script_tag(name:"creation_date", value:"2026-04-01 04:58:49 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-30 18:48:50 +0000 (Mon, 30 Mar 2026)");

  script_name("Debian: Security Advisory (DSA-6188-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-6188-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6188-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lxd' package(s) announced via the DSA-6188-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'lxd' package(s) on Debian 12, Debian 13.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"lxd", ver:"5.0.2-5+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-agent", ver:"5.0.2-5+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-client", ver:"5.0.2-5+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-migrate", ver:"5.0.2-5+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-tools", ver:"5.0.2-5+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-canonical-lxd-dev", ver:"5.0.2+git20231211.1364ae4-9+deb13u4", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd", ver:"5.0.2+git20231211.1364ae4-9+deb13u4", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-agent", ver:"5.0.2+git20231211.1364ae4-9+deb13u4", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-client", ver:"5.0.2+git20231211.1364ae4-9+deb13u4", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-migrate", ver:"5.0.2+git20231211.1364ae4-9+deb13u4", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-tools", ver:"5.0.2+git20231211.1364ae4-9+deb13u4", rls:"DEB13"))) {
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
