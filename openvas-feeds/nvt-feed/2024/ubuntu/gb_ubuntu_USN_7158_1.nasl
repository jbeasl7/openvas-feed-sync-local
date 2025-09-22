# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7158.1");
  script_cve_id("CVE-2018-25047", "CVE-2023-28447", "CVE-2024-35226");
  script_tag(name:"creation_date", value:"2024-12-13 04:08:23 +0000 (Fri, 13 Dec 2024)");
  script_version("2024-12-13T15:40:54+0000");
  script_tag(name:"last_modification", value:"2024-12-13 15:40:54 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-04 23:36:39 +0000 (Tue, 04 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-7158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7158-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7158-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'smarty3' package(s) announced via the USN-7158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Smarty incorrectly handled query parameters in
requests. An attacker could possibly use this issue to inject arbitrary
Javascript code, resulting in denial of service or potential execution of
arbitrary code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04
LTS, Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.
(CVE-2018-25047, CVE-2023-28447)

It was discovered that Smarty did not properly sanitize user input when
generating templates. An attacker could, through PHP injection, possibly
use this issue to execute arbitrary code. (CVE-2024-35226)");

  script_tag(name:"affected", value:"'smarty3' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.31+20161214.1.c7d42e4+selfpack1-3ubuntu0.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.34+20190228.1.c9f0de05+selfpack1-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.39-2ubuntu1.22.04.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.48-1ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.48-1ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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
