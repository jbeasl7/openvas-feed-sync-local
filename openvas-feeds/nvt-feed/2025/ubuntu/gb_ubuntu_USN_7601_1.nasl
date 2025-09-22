# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7601.1");
  script_cve_id("CVE-2025-5914", "CVE-2025-5915", "CVE-2025-5916", "CVE-2025-5917");
  script_tag(name:"creation_date", value:"2025-06-30 10:21:48 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 11:15:27 +0000 (Tue, 12 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7601-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7601-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7601-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-7601-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libarchive incorrectly handled certain RAR archive
files. An attacker could possibly use this issue to execute arbitrary
code or cause a denial of service. (CVE-2025-5914)

It was discovered that libarchive incorrectly handled certain RAR archive
files. An attacker could possibly use this issue to read sensitive data
or cause a denial of service. (CVE-2025-5915)

It was discovered that libarchive incorrectly handled certain WARC
archive files. If a user or automated system were tricked into processing
a specially crafted WARC archive, an attacker could use this issue to
cause libarchive to crash, resulting in a denial of service.
(CVE-2025-5916)

It was discovered that libarchive incorrectly handled certain file names
when handling prefixes and suffixes. An attacker could possibly use this
issue to cause libarchive to crash, resulting in a denial of service.
(CVE-2025-5917)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.6.0-1ubuntu1.5", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13t64", ver:"3.7.2-2ubuntu0.5", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13t64", ver:"3.7.4-1ubuntu0.3", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13t64", ver:"3.7.7-0ubuntu2.3", rls:"UBUNTU25.04"))) {
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
