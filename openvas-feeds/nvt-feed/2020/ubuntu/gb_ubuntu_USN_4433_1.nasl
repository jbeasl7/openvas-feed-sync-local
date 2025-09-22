# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844507");
  script_cve_id("CVE-2020-14556", "CVE-2020-14562", "CVE-2020-14573", "CVE-2020-14577", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");
  script_tag(name:"creation_date", value:"2020-07-24 03:00:25 +0000 (Fri, 24 Jul 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-21 02:50:09 +0000 (Tue, 21 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4433-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4433-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4433-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-lts' package(s) announced via the USN-4433-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Johannes Kuhn discovered that OpenJDK incorrectly handled access control
contexts. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2020-14556)

It was discovered that OpenJDK incorrectly handled memory allocation when
reading TIFF image files. An attacker could possibly use this issue to
cause a denial of service. (CVE-2020-14562)

It was discovered that OpenJDK incorrectly handled input data. An
attacker could possibly use this issue to insert, edit or obtain
sensitive information. (CVE-2020-14573)

Philippe Arteau discovered that OpenJDK incorrectly verified names in
TLS server's X.509 certificates. An attacker could possibly use this
issue to obtain sensitive information. (CVE-2020-14577)

It was discovered that OpenJDK incorrectly handled image files. An
attacker could possibly use this issue to obtain sensitive information.
(CVE-2020-14581)

Markus Loewe discovered that OpenJDK incorrectly handled concurrent
access in java.nio.Buffer class. An attacker could use this issue to
bypass the sandbox restrictions and cause unspecified impact.
(CVE-2020-14583)

It was discovered that OpenJDK incorrectly handled transformation of
images. An attacker could possibly use this issue to bypass sandbox
restrictions and insert, edit or obtain sensitive information.
(CVE-2020-14593)

Roman Shemyakin discovered that OpenJDK incorrectly handled XML files.
An attacker could possibly use this issue to insert, edit or obtain
sensitive information. (CVE-2020-14621)");

  script_tag(name:"affected", value:"'openjdk-lts' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.8+10-0ubuntu1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.8+10-0ubuntu1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.8+10-0ubuntu1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.8+10-0ubuntu1~18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.8+10-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.8+10-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.8+10-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.8+10-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
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
