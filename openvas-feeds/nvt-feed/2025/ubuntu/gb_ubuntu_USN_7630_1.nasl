# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7630.1");
  script_cve_id("CVE-2016-6345", "CVE-2016-6346", "CVE-2016-6347", "CVE-2016-6348", "CVE-2016-7050", "CVE-2020-10688", "CVE-2020-1695", "CVE-2020-25633", "CVE-2021-20289", "CVE-2023-0482", "CVE-2024-9622");
  script_tag(name:"creation_date", value:"2025-07-14 04:18:26 +0000 (Mon, 14 Jul 2025)");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-16 12:03:40 +0000 (Fri, 16 Jun 2017)");

  script_name("Ubuntu: Security Advisory (USN-7630-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7630-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7630-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'resteasy, resteasy3.0' package(s) announced via the USN-7630-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that RESTEasy made insufficient use of random values in
asynchronous jobs. An attacker could possibly use this issue to steal
user data. This issue only affected Ubuntu 16.04 LTS. (CVE-2016-6345)

It was discovered that RESTEasy enabled a vulnerable GZIP decompression
module by default. An attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-6346)

It was discovered that RESTEasy improperly made use of unsanitized data
while handling certain errors. An attacker could possibly use this issue
to cause a denial of service or execute arbitrary code.
This issue only affected Ubuntu 16.04 LTS. (CVE-2016-6347)

It was discovered that RESTEasy enabled a vulnerable JSON manipulation
module by default. An attacker could possibly use this issue to cause a
denial of service or execute arbitrary code.
This issue only affected Ubuntu 16.04 LTS. (CVE-2016-6348)

It was discovered that RESTEasy enabled a vulnerable deserialization
module by default. An attacker could possibly use this issue to cause a
denial of service or execute arbitrary code.
This issue only affected Ubuntu 16.04 LTS. (CVE-2016-7050)

Nikos Papadopoulos discovered that RESTEasy improperly handled URL encoding
when certain errors occur. An attacker could possibly use this issue to
modify the app's behavior for other users throughout the network.
This issue did not affect resteasy3.0 in Ubuntu 24.04 LTS, Ubuntu 24.10,
and Ubuntu 25.04. (CVE-2020-10688)

Mirko Selber discovered that RESTEasy improperly validated user input
during HTTP response construction. An attacker could possibly use this
issue to to cause a denial of service or execute arbitrary code.
This issue did not affect resteasy3.0 in Ubuntu 22.04 LTS,
Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.04. (CVE-2020-1695)

It was discovered that RESTEasy improperly handled receiving the
WebApplicationException during a client call. An attacker could possibly
use this issue to obtain potentially sensitive server information.
(CVE-2020-25633)

It was discovered that RESTEasy improperly populated exception responses
with endpoint class and method names. An attacker could possibly use this
issue to obtain potentially sensitive server information. (CVE-2021-20289)

It was discovered that RESTEasy used improper permissions when creating
temporary files. An attacker could possibly use this issue to get access to
sensitive data. (CVE-2023-0482)

It was discovered that RESTEasy improperly handled certain HTTP requests
containing ASCII control characters. An attacker could possibly use this
issue to cause a denial of service. (CVE-2024-9622)");

  script_tag(name:"affected", value:"'resteasy, resteasy3.0' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy-java", ver:"3.0.6-3ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy3.0-java", ver:"3.0.26-1~18.04.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy3.0-java", ver:"3.0.26-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy3.0-java", ver:"3.0.26-3ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy3.0-java", ver:"3.0.26-6ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy3.0-java", ver:"3.0.26-6ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy-java", ver:"3.6.2-3ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libresteasy3.0-java", ver:"3.0.26-6ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
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
