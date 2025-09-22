# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6727.2");
  script_cve_id("CVE-2023-4421", "CVE-2023-5388", "CVE-2023-6135");
  script_tag(name:"creation_date", value:"2024-04-12 04:08:49 +0000 (Fri, 12 Apr 2024)");
  script_version("2024-04-12T15:39:03+0000");
  script_tag(name:"last_modification", value:"2024-04-12 15:39:03 +0000 (Fri, 12 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-20 18:40:25 +0000 (Wed, 20 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6727-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6727-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6727-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2060906");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the USN-6727-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6727-1 fixed vulnerabilities in NSS. The update introduced a regression
when trying to load security modules on Ubuntu 20.04 LTS and Ubuntu 22.04
LTS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that NSS incorrectly handled padding when checking PKCS#1
 certificates. A remote attacker could possibly use this issue to perform
 Bleichenbacher-like attacks and recover private data. This issue only
 affected Ubuntu 20.04 LTS. (CVE-2023-4421)

 It was discovered that NSS had a timing side-channel when performing RSA
 decryption. A remote attacker could possibly use this issue to recover
 private data. (CVE-2023-5388)

 It was discovered that NSS had a timing side-channel when using certain
 NIST curves. A remote attacker could possibly use this issue to recover
 private data. (CVE-2023-6135)

 The NSS package contained outdated CA certificates. This update refreshes
 the NSS package to version 3.98 which includes the latest CA certificate
 bundle and other security improvements.");

  script_tag(name:"affected", value:"'nss' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.98-0ubuntu0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.98-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
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
