# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6847.1");
  script_cve_id("CVE-2019-11471", "CVE-2020-23109", "CVE-2023-0996", "CVE-2023-29659", "CVE-2023-49460", "CVE-2023-49462", "CVE-2023-49463", "CVE-2023-49464");
  script_tag(name:"creation_date", value:"2024-06-26 04:08:04 +0000 (Wed, 26 Jun 2024)");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-11 17:31:56 +0000 (Mon, 11 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6847-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6847-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6847-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheif' package(s) announced via the USN-6847-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libheif incorrectly handled certain image data.
An attacker could possibly use this issue to crash the program, resulting
in a denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2019-11471)

Reza Mirzazade Farkhani discovered that libheif incorrectly handled
certain image data. An attacker could possibly use this issue to crash the
program, resulting in a denial of service. This issue only affected Ubuntu
20.04 LTS. (CVE-2020-23109)

Eugene Lim discovered that libheif incorrectly handled certain image data.
An attacker could possibly use this issue to crash the program, resulting
in a denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu
20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-0996)

Min Jang discovered that libheif incorrectly handled certain image data.
An attacker could possibly use this issue to crash the program, resulting
in a denial of service. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2023-29659)

Yuchuan Meng discovered that libheif incorrectly handled certain image data.
An attacker could possibly use this issue to crash the program, resulting
in a denial of service. This issue only affected Ubuntu 23.10.
(CVE-2023-49460, CVE-2023-49462, CVE-2023-49463, CVE-2023-49464)");

  script_tag(name:"affected", value:"'libheif' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libheif-dev", ver:"1.1.0-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif1", ver:"1.1.0-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"heif-gdk-pixbuf", ver:"1.6.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif-dev", ver:"1.6.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif1", ver:"1.6.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"heif-gdk-pixbuf", ver:"1.12.0-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif-dev", ver:"1.12.0-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif1", ver:"1.12.0-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"heif-gdk-pixbuf", ver:"1.16.2-2ubuntu1.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif-dev", ver:"1.16.2-2ubuntu1.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif-plugin-libde265", ver:"1.16.2-2ubuntu1.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheif1", ver:"1.16.2-2ubuntu1.1", rls:"UBUNTU23.10"))) {
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
