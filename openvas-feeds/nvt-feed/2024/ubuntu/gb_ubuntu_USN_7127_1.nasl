# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7127.1");
  script_cve_id("CVE-2024-52530", "CVE-2024-52531", "CVE-2024-52532");
  script_tag(name:"creation_date", value:"2024-11-28 04:08:12 +0000 (Thu, 28 Nov 2024)");
  script_version("2024-11-29T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-29 05:05:36 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7127-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7127-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7127-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup3' package(s) announced via the USN-7127-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libsoup ignored certain characters at the end of
header names. A remote attacker could possibly use this issue to perform
a HTTP request smuggling attack. This issue only affected Ubuntu 22.04 LTS
and Ubuntu 24.04 LTS. (CVE-2024-52530)

It was discovered that libsoup did not correctly handle memory while
performing UTF-8 conversions. An attacker could possibly use this issue
to cause a denial of service or execute arbitrary code. (CVE-2024-52531)

It was discovered that libsoup could enter an infinite loop when reading
certain websocket data. An attacker could possibly use this issue to
cause a denial of service. (CVE-2024-52532)");

  script_tag(name:"affected", value:"'libsoup3' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.0.7-0ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.4.4-5ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.6.0-2ubuntu0.1", rls:"UBUNTU24.10"))) {
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
