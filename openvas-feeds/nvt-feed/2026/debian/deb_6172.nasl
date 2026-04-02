# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6172");
  script_cve_id("CVE-2025-43214", "CVE-2025-43457", "CVE-2025-43511", "CVE-2026-20608", "CVE-2026-20635", "CVE-2026-20636", "CVE-2026-20644", "CVE-2026-20652", "CVE-2026-20676");
  script_tag(name:"creation_date", value:"2026-03-23 04:46:52 +0000 (Mon, 23 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 14:46:38 +0000 (Fri, 13 Feb 2026)");

  script_name("Debian: Security Advisory (DSA-6172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-6172-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6172-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DSA-6172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian 12, Debian 13.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.0", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.1", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-6.0", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit-6.0", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.0", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.1", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-bin", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-dev", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.1-0", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.1-dev", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-6.0-1", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-6.0-dev", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-dev", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-doc", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.1-0", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.1-dev", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-6.0-4", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-6.0-dev", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webkit2gtk-driver", ver:"2.50.6-1~deb12u1", rls:"DEB12"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.1", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-6.0", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit-6.0", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.1", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-bin", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.1-0", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.1-dev", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-6.0-1", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-6.0-dev", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-bin", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-doc", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.1-0", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.1-dev", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-6.0-4", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-6.0-dev", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-doc", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webkit2gtk-driver", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webkitgtk-webdriver", ver:"2.50.6-1~deb13u1", rls:"DEB13"))) {
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
