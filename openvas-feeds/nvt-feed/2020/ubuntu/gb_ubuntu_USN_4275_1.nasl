# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844336");
  script_cve_id("CVE-2018-19872", "CVE-2019-18281", "CVE-2020-0569", "CVE-2020-0570");
  script_tag(name:"creation_date", value:"2020-02-11 04:00:17 +0000 (Tue, 11 Feb 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 17:54:02 +0000 (Tue, 22 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4275-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4275-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtbase-opensource-src' package(s) announced via the USN-4275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Qt incorrectly handled certain PPM images. If a user
or automated system were tricked into opening a specially crafted PPM file,
a remote attacker could cause Qt to crash, resulting in a denial of
service. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2018-19872)

It was discovered that Qt incorrectly handled certain text files. If a user
or automated system were tricked into opening a specially crafted text
file, a remote attacker could cause Qt to crash, resulting in a denial of
service. This issue only affected Ubuntu 19.10. (CVE-2019-18281)

It was discovered that Qt incorrectly searched for plugins in the current
working directory. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2020-0569)

It was discovered that Qt incorrectly searched for libraries relative to
the current working directory. An attacker could possibly use this issue to
execute arbitrary code. This issue only affected Ubuntu 19.10.
(CVE-2020-0570)");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.5.1+dfsg-16ubuntu7.7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.5.1+dfsg-16ubuntu7.7", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.9.5+dfsg-0ubuntu2.5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.9.5+dfsg-0ubuntu2.5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.12.4+dfsg-4ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.12.4+dfsg-4ubuntu1.1", rls:"UBUNTU19.10"))) {
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
