# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845078");
  script_cve_id("CVE-2021-33193", "CVE-2021-34798", "CVE-2021-36160", "CVE-2021-39275", "CVE-2021-40438");
  script_tag(name:"creation_date", value:"2021-09-29 01:00:41 +0000 (Wed, 29 Sep 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-30 15:20:22 +0000 (Thu, 30 Sep 2021)");

  script_name("Ubuntu: Security Advisory (USN-5090-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-5090-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5090-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1945311");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-5090-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5090-1 fixed vulnerabilities in Apache HTTP Server. One of the upstream
fixes introduced a regression in UDS URIs. This update fixes the problem.

Original advisory details:

 James Kettle discovered that the Apache HTTP Server HTTP/2 module
 incorrectly handled certain crafted methods. A remote attacker could
 possibly use this issue to perform request splitting or cache poisoning
 attacks. (CVE-2021-33193)

 It was discovered that the Apache HTTP Server incorrectly handled certain
 malformed requests. A remote attacker could possibly use this issue to
 cause the server to crash, resulting in a denial of service.
 (CVE-2021-34798)

 Li Zhi Xin discovered that the Apache mod_proxy_uwsgi module incorrectly
 handled certain request uri-paths. A remote attacker could possibly use
 this issue to cause the server to crash, resulting in a denial of service.
 This issue only affected Ubuntu 20.04 LTS and Ubuntu 21.04.
 (CVE-2021-36160)

 It was discovered that the Apache HTTP Server incorrectly handled escaping
 quotes. If the server was configured with third-party modules, a remote
 attacker could use this issue to cause the server to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2021-39275)

 It was discovered that the Apache mod_proxy module incorrectly handled
 certain request uri-paths. A remote attacker could possibly use this issue
 to cause the server to forward requests to arbitrary origin servers.
 (CVE-2021-40438)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.29-1ubuntu4.18", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.18", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.41-4ubuntu3.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.46-4ubuntu1.3", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.46-4ubuntu1.3", rls:"UBUNTU21.04"))) {
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
