# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7199.1");
  script_cve_id("CVE-2015-1283", "CVE-2016-0718", "CVE-2016-4472", "CVE-2018-20843", "CVE-2019-15903", "CVE-2021-46143", "CVE-2022-22822", "CVE-2022-22823", "CVE-2022-22824", "CVE-2022-22825", "CVE-2022-22826", "CVE-2022-22827");
  script_tag(name:"creation_date", value:"2025-01-13 07:33:18 +0000 (Mon, 13 Jan 2025)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-13 20:41:52 +0000 (Thu, 13 Jan 2022)");

  script_name("Ubuntu: Security Advisory (USN-7199-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7199-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7199-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxmltok' package(s) announced via the USN-7199-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Expat, contained within the xmltok library,
incorrectly handled malformed XML data. If a user or application were
tricked into opening a crafted XML file, an attacker could cause a denial
of service, or possibly execute arbitrary code. (CVE-2015-1283,
CVE-2016-0718, CVE-2016-4472, CVE-2019-15903)

It was discovered that Expat, contained within the xmltok library,
incorrectly handled XML data containing a large number of colons, which
could lead to excessive resource consumption. If a user or application
were tricked into opening a crafted XML file, an attacker could possibly
use this issue to cause a denial of service. (CVE-2018-20843)

It was discovered that Expat, contained within the xmltok library,
incorrectly handled certain input, which could lead to an integer
overflow. If a user or application were tricked into opening a crafted XML
file, an attacker could possibly use this issue to cause a denial of
service. (CVE-2021-46143, CVE-2022-22822, CVE-2022-22823, CVE-2022-22824,
CVE-2022-22825, CVE-2022-22826, CVE-2022-22827)");

  script_tag(name:"affected", value:"'libxmltok' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-4ubuntu0.18.04.1~esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-4ubuntu0.20.04.1~esm4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-4ubuntu0.22.04.1~esm4", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1t64", ver:"1.2-4.1ubuntu2.24.0.4.1+esm2", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1t64", ver:"1.2-4.1ubuntu3.1", rls:"UBUNTU24.10"))) {
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
