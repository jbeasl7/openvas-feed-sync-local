# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6948.1");
  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592", "CVE-2020-28243", "CVE-2020-28972", "CVE-2020-35662", "CVE-2021-25281", "CVE-2021-25282", "CVE-2021-25283", "CVE-2021-25284", "CVE-2021-3148", "CVE-2021-3197");
  script_tag(name:"creation_date", value:"2024-08-09 04:08:33 +0000 (Fri, 09 Aug 2024)");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-05 14:38:41 +0000 (Fri, 05 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-6948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6948-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6948-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the USN-6948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Salt incorrectly handled crafted web requests.
A remote attacker could possibly use this issue to run arbitrary
commands. (CVE-2020-16846)

It was discovered that Salt incorrectly created certificates with weak
file permissions. (CVE-2020-17490)

It was discovered that Salt incorrectly handled credential validation.
A remote attacker could possibly use this issue to bypass authentication.
(CVE-2020-25592)

It was discovered that Salt incorrectly handled crafted process names.
An attacker could possibly use this issue to run arbitrary commands.
This issue only affected Ubuntu 18.04 LTS. (CVE-2020-28243)

It was discovered that Salt incorrectly handled validation of SSL/TLS
certificates. A remote attacker could possibly use this issue to spoof
a trusted entity. (CVE-2020-28972, CVE-2020-35662)

It was discovered that Salt incorrectly handled credential validation.
A remote attacker could possibly use this issue to run arbitrary code.
(CVE-2021-25281)

It was discovered that Salt incorrectly handled crafted paths. A remote
attacker could possibly use this issue to perform directory traversal.
(CVE-2021-25282)

It was discovered that Salt incorrectly handled template rendering. A
remote attacker could possibly this issue to run arbitrary code.
(CVE-2021-25283)

It was discovered that Salt incorrectly handled logging. An attacker
could possibly use this issue to discover credentials. This issue only
affected Ubuntu 18.04 LTS. (CVE-2021-25284)

It was discovered that Salt incorrectly handled crafted web requests.
A remote attacker could possibly use this issue to run arbitrary
commands. This issue only affected Ubuntu 18.04 LTS. (CVE-2021-3148)

It was discovered that Salt incorrectly handled input sanitization.
A remote attacker could possibly use this issue to run arbitrary
commands. (CVE-2021-3197)");

  script_tag(name:"affected", value:"'salt' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2015.8.8+ds-1ubuntu0.1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2017.7.4+dfsg1-1ubuntu18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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
