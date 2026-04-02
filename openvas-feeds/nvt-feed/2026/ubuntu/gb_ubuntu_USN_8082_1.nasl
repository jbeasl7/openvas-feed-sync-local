# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8082.1");
  script_cve_id("CVE-2025-5473", "CVE-2025-6035");
  script_tag(name:"creation_date", value:"2026-03-11 04:34:17 +0000 (Wed, 11 Mar 2026)");
  script_version("2026-03-12T05:56:11+0000");
  script_tag(name:"last_modification", value:"2026-03-12 05:56:11 +0000 (Thu, 12 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-18 16:00:12 +0000 (Mon, 18 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-8082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8082-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8082-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the USN-8082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Randrianantenaina discovered that GIMP incorrectly handled certain
malformed ICO files. An attacker could possibly use this to cause a denial
of service or execute arbitrary code. (CVE-2025-5473)

Seungho Kim discovered that GIMP incorrectly handled certain memory
operations when running the despeckle plugin. An attacker could possibly
use this to cause a denial of service or execute arbitrary code.
(CVE-2025-6035)");

  script_tag(name:"affected", value:"'gimp' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.8.16-1ubuntu1.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.8.16-1ubuntu1.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.8.22-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.8.22-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.10.18-1ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.10.18-1ubuntu0.1+esm3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.10.30-1ubuntu0.1+esm3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.10.30-1ubuntu0.1+esm3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.10.36-3ubuntu0.24.04.1+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0t64", ver:"2.10.36-3ubuntu0.24.04.1+esm3", rls:"UBUNTU24.04 LTS"))) {
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
