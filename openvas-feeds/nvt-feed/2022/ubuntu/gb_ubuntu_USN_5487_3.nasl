# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845422");
  script_cve_id("CVE-2022-26377", "CVE-2022-28614", "CVE-2022-28615", "CVE-2022-29404", "CVE-2022-30522", "CVE-2022-30556", "CVE-2022-31813");
  script_tag(name:"creation_date", value:"2022-06-24 01:00:44 +0000 (Fri, 24 Jun 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-17 19:19:40 +0000 (Fri, 17 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5487-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5487-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5487-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1979577");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1979641");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-5487-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5487-1 fixed several vulnerabilities in Apache HTTP Server.
Unfortunately it caused regressions. USN-5487-2 reverted the
patches that caused the regression in Ubuntu 14.04 ESM for further
investigation. This update re-adds the security fixes for Ubuntu
14.04 ESM and fixes two different regressions: one affecting mod_proxy
only in Ubuntu 14.04 ESM and another in mod_sed affecting also Ubuntu 16.04 ESM
and Ubuntu 18.04 LTS.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Apache HTTP Server mod_proxy_ajp incorrectly handled
 certain crafted request. A remote attacker could possibly use this issue to
 perform an HTTP Request Smuggling attack. (CVE-2022-26377)

 It was discovered that Apache HTTP Server incorrectly handled certain
 request. An attacker could possibly use this issue to cause a denial
 of service. (CVE-2022-28614)

 It was discovered that Apache HTTP Server incorrectly handled certain request.
 An attacker could possibly use this issue to cause a crash or expose
 sensitive information. (CVE-2022-28615)

 It was discovered that Apache HTTP Server incorrectly handled certain request.
 An attacker could possibly use this issue to cause a denial of service.
 (CVE-2022-29404)

 It was discovered that Apache HTTP Server incorrectly handled certain
 request. An attacker could possibly use this issue to cause a crash.
 (CVE-2022-30522)

 It was discovered that Apache HTTP Server incorrectly handled certain request.
 An attacker could possibly use this issue to execute arbitrary code or cause
 a crash. (CVE-2022-30556)

 It was discovered that Apache HTTP Server incorrectly handled certain request.
 An attacker could possibly use this issue to bypass IP based authentication.
 (CVE-2022-31813)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.7-1ubuntu4.22+esm8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.7-1ubuntu4.22+esm8", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.18-2ubuntu3.17+esm7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.18-2ubuntu3.17+esm7", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.29-1ubuntu4.25", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.25", rls:"UBUNTU18.04 LTS"))) {
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
