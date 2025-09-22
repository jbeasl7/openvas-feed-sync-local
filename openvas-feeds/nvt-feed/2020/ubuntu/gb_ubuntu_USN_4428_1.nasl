# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844501");
  script_cve_id("CVE-2019-17514", "CVE-2019-20907", "CVE-2019-9674", "CVE-2020-14422");
  script_tag(name:"creation_date", value:"2020-07-23 03:00:53 +0000 (Thu, 23 Jul 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-20 14:38:39 +0000 (Thu, 20 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-4428-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4428-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4428-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.4, python3.5, python3.6, python3.8' package(s) announced via the USN-4428-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python documentation had a misleading information.
A security issue could be possibly caused by wrong assumptions of this information.
This issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM, Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-17514)

It was discovered that Python incorrectly handled certain TAR archives.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2019-20907)

It was discovered that incorrectly handled certain ZIP files. An attacker
could possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM, Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-9674)

It was discovered that Python incorrectly handled certain IP values.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-14422)");

  script_tag(name:"affected", value:"'python2.7, python3.4, python3.5, python3.6, python3.8' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.3-0ubuntu3.18", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.3-0ubuntu3.18", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.6+esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.6-8ubuntu0.6+esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4", ver:"3.4.3-1ubuntu1~14.04.7+esm7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4-minimal", ver:"3.4.3-1ubuntu1~14.04.7+esm7", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.12-1ubuntu0~16.04.12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.12-1ubuntu0~16.04.12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.2-2ubuntu0~16.04.11", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.2-2ubuntu0~16.04.11", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.17-1~18.04ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.17-1~18.04ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6", ver:"3.6.9-1~18.04ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6-minimal", ver:"3.6.9-1~18.04ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.2-1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.2-1ubuntu1.2", rls:"UBUNTU20.04 LTS"))) {
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
