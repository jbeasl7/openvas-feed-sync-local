# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7147.1");
  script_cve_id("CVE-2016-6802", "CVE-2023-34478", "CVE-2023-46749", "CVE-2023-46750");
  script_tag(name:"creation_date", value:"2024-12-11 09:10:30 +0000 (Wed, 11 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:15:33 +0000 (Tue, 01 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-7147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7147-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7147-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shiro' package(s) announced via the USN-7147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Apache Shiro incorrectly handled path traversal when
used with other web frameworks or path rewriting. An attacker could
possibly use this issue to obtain sensitive information or administrative
privileges. This update provides the corresponding fix for Ubuntu 24.04 LTS
and Ubuntu 24.10. (CVE-2023-34478, CVE-2023-46749)

It was discovered that Apache Shiro incorrectly handled web redirects when
used together with the form authentication method. An attacker could
possibly use this issue to perform phishing attacks. This update provides
the corresponding fix for Ubuntu 24.04 LTS and Ubuntu 24.10.
(CVE-2023-46750)

It was discovered that Apache Shiro incorrectly handled requests through
servlet filtering. An attacker could possibly use this issue to obtain
administrative privileges. This update provides the corresponding fix for
Ubuntu 16.04 LTS. (CVE-2016-6802)");

  script_tag(name:"affected", value:"'shiro' package(s) on Ubuntu 16.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libshiro-java", ver:"1.2.4-1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libshiro-java", ver:"1.3.2-5ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libshiro-java", ver:"1.3.2-5ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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
