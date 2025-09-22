# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7106.1");
  script_cve_id("CVE-2023-28708", "CVE-2023-41080", "CVE-2023-42795", "CVE-2023-45648", "CVE-2024-23672");
  script_tag(name:"creation_date", value:"2024-11-14 04:07:54 +0000 (Thu, 14 Nov 2024)");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-31 17:05:13 +0000 (Thu, 31 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-7106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7106-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7106-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat9' package(s) announced via the USN-7106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat did not include the secure attribute for
session cookies when using the RemoteIpFilter with requests from a
reverse proxy. An attacker could possibly use this issue to leak
sensitive information. (CVE-2023-28708)

It was discovered that Tomcat had a vulnerability in its FORM
authentication feature, leading to an open redirect attack. An attacker
could possibly use this issue to perform phishing attacks. (CVE-2023-41080)

It was discovered that Tomcat incorrectly recycled certain objects,
which could lead to information leaking from one request to the next.
An attacker could potentially use this issue to leak sensitive
information. (CVE-2023-42795)

It was discovered that Tomcat incorrectly handled HTTP trailer headers. A
remote attacker could possibly use this issue to perform HTTP request
smuggling. (CVE-2023-45648)

It was discovered that Tomcat incorrectly handled socket cleanup, which
could lead to websocket connections staying open. An attacker could
possibly use this issue to cause a denial of service. (CVE-2024-23672)");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.16-3ubuntu0.18.04.2+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.16-3ubuntu0.18.04.2+esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.31-1ubuntu0.8", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.31-1ubuntu0.8", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.58-1ubuntu0.1+esm4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.58-1ubuntu0.1+esm4", rls:"UBUNTU22.04 LTS"))) {
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
