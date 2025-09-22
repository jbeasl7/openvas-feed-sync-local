# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6932.1");
  script_cve_id("CVE-2024-21131", "CVE-2024-21138", "CVE-2024-21140", "CVE-2024-21145", "CVE-2024-21147");
  script_tag(name:"creation_date", value:"2024-07-31 12:49:11 +0000 (Wed, 31 Jul 2024)");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 23:15:16 +0000 (Tue, 16 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-6932-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6932-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6932-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-21' package(s) announced via the USN-6932-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Hotspot component of OpenJDK 21 was not properly
bounding certain UTF-8 strings, which could lead to a buffer overflow. An
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. (CVE-2024-21131)

It was discovered that the Hotspot component of OpenJDK 21 could be made to
run into an infinite loop. If an automated system were tricked into
processing excessively large symbols, an attacker could possibly use this
issue to cause a denial of service. (CVE-2024-21138)

It was discovered that the Hotspot component of OpenJDK 21 did not
properly perform range check elimination. An attacker could possibly use
this issue to cause a denial of service, execute arbitrary code or bypass
Java sandbox restrictions. (CVE-2024-21140)

Sergey Bylokhov discovered that OpenJDK 21 did not properly manage memory
when handling 2D images. An attacker could possibly use this issue to
obtain sensitive information. (CVE-2024-21145)

It was discovered that the Hotspot component of OpenJDK 21 incorrectly
handled memory when performing range check elimination under certain
circumstances. An attacker could possibly use this issue to cause a
denial of service, execute arbitrary code or bypass Java sandbox
restrictions. (CVE-2024-21147)");

  script_tag(name:"affected", value:"'openjdk-21' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.4+7-1ubuntu2~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.4+7-1ubuntu2~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.4+7-1ubuntu2~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.4+7-1ubuntu2~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.4+7-1ubuntu2~20.04", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.4+7-1ubuntu2~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.4+7-1ubuntu2~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.4+7-1ubuntu2~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.4+7-1ubuntu2~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.4+7-1ubuntu2~22.04", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.4+7-1ubuntu2~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.4+7-1ubuntu2~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.4+7-1ubuntu2~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.4+7-1ubuntu2~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.4+7-1ubuntu2~24.04", rls:"UBUNTU24.04 LTS"))) {
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
