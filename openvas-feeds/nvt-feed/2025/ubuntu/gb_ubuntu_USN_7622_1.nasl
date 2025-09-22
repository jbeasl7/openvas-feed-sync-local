# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7622.1");
  script_cve_id("CVE-2012-6708", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023");
  script_tag(name:"creation_date", value:"2025-07-10 08:14:31 +0000 (Thu, 10 Jul 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-07 14:13:42 +0000 (Thu, 07 May 2020)");

  script_name("Ubuntu: Security Advisory (USN-7622-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7622-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7622-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jquery' package(s) announced via the USN-7622-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that jQuery did not correctly handle HTML tags. An
attacker could possibly use this issue to execute a cross-site scripting
(XSS) attack. This issue only affected Ubuntu 14.04 LTS. (CVE-2012-6708)

It was discovered that jQuery did not correctly handle unsanitized source
objects due to prototype pollution. An attacker could possibly use this
issue to execute a cross-site scripting (XSS) attack. (CVE-2019-11358)

Masato Kinugawa discovered that jQuery did not correctly sanitize certain
HTML elements. An attacker could possibly use this issue to execute a
cross-site scripting (XSS) attack. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2020-11022)

Masato Kinugawa discovered that jQuery did not correctly sanitize certain
HTML elements. An attacker could possibly use this issue to execute a
cross-site scripting (XSS) attack. This issue only affected
Ubuntu 18.04 LTS. (CVE-2020-11023)");

  script_tag(name:"affected", value:"'jquery' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery", ver:"1.7.2+dfsg-2ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery", ver:"1.11.3+dfsg-4ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery", ver:"3.2.1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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
