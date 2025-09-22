# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7272.1");
  script_cve_id("CVE-2022-24894", "CVE-2022-24895", "CVE-2023-46734", "CVE-2024-50340", "CVE-2024-50341", "CVE-2024-50342", "CVE-2024-50343", "CVE-2024-50345", "CVE-2024-51996");
  script_tag(name:"creation_date", value:"2025-02-19 11:55:10 +0000 (Wed, 19 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 14:25:50 +0000 (Wed, 15 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-7272-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7272-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7272-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'symfony' package(s) announced via the USN-7272-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Soner Sayakci discovered that Symfony incorrectly handled cookie storage in
the web cache. An attacker could possibly use this issue to obtain
sensitive information and access unauthorized resources. (CVE-2022-24894)

Marco Squarcina discovered that Symfony incorrectly handled the storage of
user session information. An attacker could possibly use this issue to
perform a cross-site request forgery (CSRF) attack. (CVE-2022-24895)

Pierre Rudloff discovered that Symfony incorrectly checked HTML input. An
attacker could possibly use this issue to perform cross site scripting.
(CVE-2023-46734)

Vladimir Dusheyko discovered that Symfony incorrectly sanitized special
input with a PHP directive in URL query strings. An attacker could possibly
use this issue to expose sensitive information or cause a denial of
service. This issue only affected Ubuntu 24.04 LTS and Ubuntu 22.04 LTS.
(CVE-2024-50340)

Oleg Andreyev, Antoine Makdessi, and Moritz Rauch discovered that Symfony
incorrectly handled user authentication. An attacker could possibly use
this issue to access unauthorized resources and expose sensitive
information. This issue was only addressed in Ubuntu 24.04 LTS.
(CVE-2024-50341, CVE-2024-51996)

Linus Karlsson and Chris Smith discovered that Symfony returned internal
host information during host resolution. An attacker could possibly use
this issue to obtain sensitive information. This issue only affected Ubuntu
24.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-50342)

It was discovered that Symfony incorrectly parsed user input through
regular expressions. An attacker could possibly use this issue to expose
sensitive information. (CVE-2024-50343)

Sam Mush discovered that Symfony incorrectly parsed URIs with special
characters. An attacker could possibly use this issue to perform phishing
attacks. (CVE-2024-50345)");

  script_tag(name:"affected", value:"'symfony' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"4.3.8+dfsg-1ubuntu1+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"5.4.4+dfsg-1ubuntu8+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"6.4.5+dfsg-3ubuntu3+esm1", rls:"UBUNTU24.04 LTS"))) {
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
