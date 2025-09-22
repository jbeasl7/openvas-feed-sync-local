# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6910.1");
  script_cve_id("CVE-2015-7559", "CVE-2018-11775", "CVE-2020-13920", "CVE-2021-26117", "CVE-2022-41678", "CVE-2023-46604");
  script_tag(name:"creation_date", value:"2024-07-24 04:08:24 +0000 (Wed, 24 Jul 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 14:28:20 +0000 (Wed, 08 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6910-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6910-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6910-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'activemq' package(s) announced via the USN-6910-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chess Hazlett discovered that Apache ActiveMQ incorrectly handled certain
commands. A remote attacker could possibly use this issue to terminate
the program, resulting in a denial of service. This issue only affected
Ubuntu 16.04 LTS. (CVE-2015-7559)

Peter Stockli discovered that Apache ActiveMQ incorrectly handled
hostname verification. A remote attacker could possibly use this issue
to perform a person-in-the-middle attack. This issue only affected Ubuntu
16.04 LTS. (CVE-2018-11775)

Jonathan Gallimore and Colm O hEigeartaigh discovered that Apache
ActiveMQ incorrectly handled authentication in certain functions.
A remote attacker could possibly use this issue to perform a
person-in-the-middle attack. This issue only affected Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-13920)

Gregor Tudan discovered that Apache ActiveMQ incorrectly handled
LDAP authentication. A remote attacker could possibly use this issue
to acquire unauthenticated access. This issue only affected Ubuntu 16.04
LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2021-26117)

It was discovered that Apache ActiveMQ incorrectly handled
authentication. A remote attacker could possibly use this issue to run
arbitrary code. (CVE-2022-41678)

It was discovered that Apache ActiveMQ incorrectly handled
deserialization. A remote attacker could possibly use this issue to run
arbitrary shell commands. (CVE-2023-46604)");

  script_tag(name:"affected", value:"'activemq' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"activemq", ver:"5.13.2+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.13.2+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"activemq", ver:"5.15.8-2~18.04.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.15.8-2~18.04.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"activemq", ver:"5.15.11-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.15.11-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"activemq", ver:"5.16.1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.16.1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
