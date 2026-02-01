# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7963.1");
  script_cve_id("CVE-2025-66293", "CVE-2026-22695", "CVE-2026-22801");
  script_tag(name:"creation_date", value:"2026-01-16 04:21:19 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 18:58:18 +0000 (Wed, 21 Jan 2026)");

  script_name("Ubuntu: Security Advisory (USN-7963-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7963-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7963-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng1.6' package(s) announced via the USN-7963-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the libpng simplified API incorrectly processed
palette PNG images with partial transparency and gamma correction. If a
user or automated system were tricked into opening a specially crafted PNG
file, an attacker could use this issue to cause libpng to crash, resulting
in a denial of service. (CVE-2025-66293)

Petr Simecek, Stanislav Fort and Pavel Kohout discovered that the libpng
simplified API incorrectly processed interlaced 16-bit PNGs with 8-bit
output format and non-minimal row strides. If a user or automated system
were tricked into opening a specially crafted PNG file, an attacker could
use this issue to cause libpng to crash, resulting in a denial of service.
(CVE-2026-22695)

Cosmin Truta discovered that the libpng simplified API incorrectly handled
invalid row strides. If a user or automated system were tricked into
opening a specially crafted PNG file, an attacker could use this issue to
cause libpng to crash, resulting in a denial of service. (CVE-2026-22801)");

  script_tag(name:"affected", value:"'libpng1.6' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpng16-16", ver:"1.6.37-3ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpng16-16t64", ver:"1.6.43-5ubuntu0.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libpng16-16t64", ver:"1.6.47-1.1ubuntu0.3", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpng16-16t64", ver:"1.6.50-1ubuntu0.3", rls:"UBUNTU25.10"))) {
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
