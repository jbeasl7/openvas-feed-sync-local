# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6167");
  script_cve_id("CVE-2026-2921");
  script_tag(name:"creation_date", value:"2026-03-18 04:41:41 +0000 (Wed, 18 Mar 2026)");
  script_version("2026-03-18T05:59:10+0000");
  script_tag(name:"last_modification", value:"2026-03-18 05:59:10 +0000 (Wed, 18 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-6167-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-6167-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6167-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-base1.0' package(s) announced via the DSA-6167-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'gst-plugins-base1.0' package(s) on Debian 12, Debian 13.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gst-plugins-base-1.0", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-alsa", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gl", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-apps", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-x", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-gl1.0-0", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-0", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-dev", ver:"1.22.0-3+deb12u6", rls:"DEB12"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gst-plugins-base-1.0", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-alsa", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gl", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-base-apps", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-x", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-gl1.0-0", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-0", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-base1.0-dev", ver:"1.26.2-1+deb13u1", rls:"DEB13"))) {
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
