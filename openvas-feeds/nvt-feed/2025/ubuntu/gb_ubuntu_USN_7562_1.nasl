# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7562.1");
  script_cve_id("CVE-2023-28708", "CVE-2023-42795", "CVE-2023-45648", "CVE-2024-21733", "CVE-2024-23672", "CVE-2024-24549", "CVE-2024-34750", "CVE-2024-38286");
  script_tag(name:"creation_date", value:"2025-06-11 04:09:16 +0000 (Wed, 11 Jun 2025)");
  script_version("2025-06-11T05:40:41+0000");
  script_tag(name:"last_modification", value:"2025-06-11 05:40:41 +0000 (Wed, 11 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 16:15:56 +0000 (Tue, 11 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7562-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7562-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7562-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8, tomcat9, tomcat10' package(s) announced via the USN-7562-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat did not include the secure attribute for
session cookies when using the RemoteIpFilter with requests from a reverse
proxy. An attacker could possibly use this issue to leak sensitive
information. This issue was fixed for tomcat8 on Ubuntu 18.04 LTS and for
tomcat9 on Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04.
(CVE-2023-28708)

It was discovered that Tomcat incorrectly recycled
certain objects, which could lead to information leaking from one request
to the next. An attacker could potentially use this issue to leak sensitive
information. This issue was fixed for tomcat8 on Ubuntu 18.04 LTS and for
tomcat9 on Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04.
(CVE-2023-42795)

It was discovered that Tomcat incorrectly handled HTTP
trailer headers. A remote attacker could possibly use this issue to perform
HTTP request smuggling. This issue was fixed for tomcat8 on Ubuntu 18.04
LTS and for tomcat9 on Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04.
(CVE-2023-45648)

It was discovered that Tomcat incorrectly handled
incomplete POST requests, which could cause error responses to contain data
from previous requests. An attacker could potentially use this issue to
leak sensitive information. This issue was fixed for tomcat8 on Ubuntu
18.04 LTS and for tomcat9 on Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2024-21733)

It was discovered that Tomcat incorrectly handled socket
cleanup, which could lead to websocket connections staying open. An
attacker could possibly use this issue to cause a denial of service. This
issue was fixed for tomcat8 on Ubuntu 18.04 LTS, tomcat9 on Ubuntu 24.04
LTS, Ubuntu 24.10, and Ubuntu 25.04, and for tomcat10 on Ubuntu 24.04 LTS.
(CVE-2024-23672)

It was discovered that Tomcat incorrectly handled HTTP/2
requests that exceeded configured header limits. An attacker could possibly
use this issue to cause a denial of service. (CVE-2024-24549)

It was discovered that Tomcat incorrectly handled some cases of excessive HTTP
headers when processing HTTP/2 streams. This led to miscounting of active
streams and incorrect timeout handling. An attacker could possibly use this
issue to cause connections to remain open indefinitely, leading to a denial
of service. This issue was fixed for tomcat9 on Ubuntu 22.04 LTS, Ubuntu
24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04, and for tomcat10 on Ubuntu
24.04 LTS. (CVE-2024-34750)

It was discovered that Tomcat incorrectly
handled TLS handshake processes under certain configurations. An attacker
could possibly use this issue to cause a denial of service. This issue was
fixed for tomcat9 on Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04, and for tomcat10 on
Ubuntu 24.04 LTS. (CVE-2024-38286)");

  script_tag(name:"affected", value:"'tomcat8, tomcat9, tomcat10' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.39-1ubuntu1~18.04.3+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.16-3ubuntu0.18.04.2+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.39-1ubuntu1~18.04.3+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.16-3ubuntu0.18.04.2+esm7", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.31-1ubuntu0.9+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.31-1ubuntu0.9+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.58-1ubuntu0.2+esm3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.58-1ubuntu0.2+esm3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat10-java", ver:"10.1.16-1ubuntu0.1~esm2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.70-2ubuntu0.1+esm2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10", ver:"10.1.16-1ubuntu0.1~esm2", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.70-2ubuntu1.24.10.2", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.70-2ubuntu1.25.04.2", rls:"UBUNTU25.04"))) {
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
