# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843239");
  script_cve_id("CVE-2017-2820", "CVE-2017-7511", "CVE-2017-7515", "CVE-2017-9083", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775");
  script_tag(name:"creation_date", value:"2017-07-14 10:24:55 +0000 (Fri, 14 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-17 15:28:38 +0000 (Mon, 17 Jul 2017)");

  script_name("Ubuntu: Security Advisory (USN-3350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3350-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3350-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-3350-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aleksandar Nikolic discovered that poppler incorrectly handled JPEG 2000
images. If a user or automated system were tricked into opening a crafted
PDF file, an attacker could cause a denial of service or possibly execute
arbitrary code with privileges of the user invoking the program.
(CVE-2017-2820)

Jiaqi Peng discovered that the poppler pdfunite tool incorrectly parsed
certain malformed PDF documents. If a user or automated system were tricked
into opening a crafted PDF file, an attacker could cause poppler to crash,
resulting in a denial of service. (CVE-2017-7511)

It was discovered that the poppler pdfunite tool incorrectly parsed certain
malformed PDF documents. If a user or automated system were tricked into
opening a crafted PDF file, an attacker could cause poppler to hang,
resulting in a denial of service. (CVE-2017-7515)

It was discovered that poppler incorrectly handled JPEG 2000 images. If a
user or automated system were tricked into opening a crafted PDF file, an
attacker could cause cause poppler to crash, resulting in a denial of
service. (CVE-2017-9083)

It was discovered that poppler incorrectly handled memory when processing
PDF documents. If a user or automated system were tricked into opening a
crafted PDF file, an attacker could cause poppler to consume resources,
resulting in a denial of service. (CVE-2017-9406, CVE-2017-9408)

Alberto Garcia, Francisco Oca, and Suleman Ali discovered that the poppler
pdftocairo tool incorrectly parsed certain malformed PDF documents. If a
user or automated system were tricked into opening a crafted PDF file, an
attacker could cause poppler to crash, resulting in a denial of service.
(CVE-2017-9775)");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler44", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.24.5-2ubuntu4.5", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler58", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.41.0-0ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0v5", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler61", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.44.0-3ubuntu2.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0v5", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-4", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt5-1", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler64", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.48.0-2ubuntu2.1", rls:"UBUNTU17.04"))) {
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
