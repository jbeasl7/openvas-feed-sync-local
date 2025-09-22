# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7217.1");
  script_cve_id("CVE-2017-5886", "CVE-2018-11255", "CVE-2018-12983", "CVE-2018-20797", "CVE-2018-5308", "CVE-2018-8002", "CVE-2019-10723", "CVE-2020-18971", "CVE-2021-30470", "CVE-2021-30471");
  script_tag(name:"creation_date", value:"2025-01-21 04:07:48 +0000 (Tue, 21 Jan 2025)");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 19:05:21 +0000 (Mon, 26 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-7217-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7217-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7217-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpodofo' package(s) announced via the USN-7217-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the PoDoFo library could dereference a NULL pointer
when getting the number of pages in a PDF. If a user or application were
tricked into opening a crafted PDF file, an attacker could possibly use
this issue to cause a denial of service. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2018-11255)

It was discovered that PoDoFo library incorrectly handled memory when
computing an encryption key, which could lead to a buffer overflow. If a
user or application were tricked into opening a crafted PDF file, an
attacker could possibly use this issue to cause a denial of service.
(CVE-2018-12983)

It was discovered that the PoDoFo library incorrectly handled memory
allocation. If a user or application were tricked into opening a crafted
PDF file, an attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2018-20797)

It was discovered that the PoDoFo library did not properly validate memcpy
arguments. If a user or application were tricked into opening a crafted
PDF file, an attacker could possibly use this issue to cause a denial of
service or execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2018-5308)

It was discovered that the PoDoFo library incorrectly handled memory in
the GetNextToken function, which could lead to a buffer overflow. If a
user or application were tricked into opening a crafted PDF file, an
attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2017-5886)

It was discovered that the PoDoFo library could enter an infinite loop,
which could lead to a stack overflow. If a user or application were
tricked into opening a crafted PDF file, an attacker could possibly use
this issue to cause a denial of service or execute arbitrary code. This
issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2018-8002, CVE-2020-18971, CVE-2021-30471, CVE-2021-30470)

It was discovered that the PoDoFo library incorrectly handled memory
allocation due to nInitialSize not being validated. If a user or
application were tricked into opening a crafted PDF file, an attacker
could possibly use this issue to cause a denial of service. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2019-10723)");

  script_tag(name:"affected", value:"'libpodofo' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo0.9.0", ver:"0.9.0-1.2ubuntu0.1~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo-utils", ver:"0.9.3-4ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo0.9.3", ver:"0.9.3-4ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo-utils", ver:"0.9.5-9ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo0.9.5", ver:"0.9.5-9ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo-utils", ver:"0.9.6+dfsg-5ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo0.9.6", ver:"0.9.6+dfsg-5ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo-utils", ver:"0.9.7+dfsg-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpodofo0.9.7", ver:"0.9.7+dfsg-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
