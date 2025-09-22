# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7176.1");
  script_cve_id("CVE-2024-47537", "CVE-2024-47539", "CVE-2024-47540", "CVE-2024-47543", "CVE-2024-47544", "CVE-2024-47545", "CVE-2024-47546", "CVE-2024-47596", "CVE-2024-47597", "CVE-2024-47598", "CVE-2024-47599", "CVE-2024-47601", "CVE-2024-47602", "CVE-2024-47603", "CVE-2024-47606", "CVE-2024-47613", "CVE-2024-47774", "CVE-2024-47775", "CVE-2024-47776", "CVE-2024-47777", "CVE-2024-47778", "CVE-2024-47834");
  script_tag(name:"creation_date", value:"2024-12-19 04:08:24 +0000 (Thu, 19 Dec 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:55:43 +0000 (Wed, 18 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-7176-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7176-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7176-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst-plugins-good1.0' package(s) announced via the USN-7176-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Antonio Morales discovered that GStreamer Good Plugins incorrectly handled
certain malformed media files. An attacker could use these issues to cause
GStreamer Good Plugins to crash, resulting in a denial of service, or
possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'gst-plugins-good1.0' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gtk3", ver:"1.16.3-0ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-good", ver:"1.16.3-0ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-pulseaudio", ver:"1.16.3-0ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt5", ver:"1.16.3-0ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-good1.0-0", ver:"1.16.3-0ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gtk3", ver:"1.20.3-0ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-good", ver:"1.20.3-0ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-pulseaudio", ver:"1.20.3-0ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt5", ver:"1.20.3-0ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-good1.0-0", ver:"1.20.3-0ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gtk3", ver:"1.24.2-1ubuntu1.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-good", ver:"1.24.2-1ubuntu1.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-pulseaudio", ver:"1.24.2-1ubuntu1.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt5", ver:"1.24.2-1ubuntu1.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt6", ver:"1.24.2-1ubuntu1.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-good1.0-0", ver:"1.24.2-1ubuntu1.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-gtk3", ver:"1.24.8-1ubuntu1.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-plugins-good", ver:"1.24.8-1ubuntu1.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-pulseaudio", ver:"1.24.8-1ubuntu1.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt5", ver:"1.24.8-1ubuntu1.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer1.0-qt6", ver:"1.24.8-1ubuntu1.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgstreamer-plugins-good1.0-0", ver:"1.24.8-1ubuntu1.1", rls:"UBUNTU24.10"))) {
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
