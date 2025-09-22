# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7639.2");
  script_cve_id("CVE-2024-42516", "CVE-2024-43204", "CVE-2024-47252", "CVE-2025-23048", "CVE-2025-49630", "CVE-2025-49812", "CVE-2025-53020");
  script_tag(name:"creation_date", value:"2025-08-20 04:04:43 +0000 (Wed, 20 Aug 2025)");
  script_version("2025-08-20T05:40:05+0000");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7639-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7639-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7639-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2119395");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-7639-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7639-1 fixed several vulnerabilities in Apache. This update
provides the corresponding update for Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, Ubuntu 20.04 LTS, and addressed a regression
fix (LP: #2119395). CVE-2025-49630 and CVE-2025-53020 only
affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that the Apache HTTP Server incorrectly handled
 certain Content-Type response headers. A remote attacker could
 possibly use this issue to perform HTTP response splitting attacks.
 (CVE-2024-42516)

 xiaojunjie discovered that the Apache HTTP Server mod_proxy module
 incorrectly handled certain requests. A remote attacker could
 possibly use this issue to send outbound proxy requests to an
 arbitrary URL. (CVE-2024-43204)

 John Runyon discovered that the Apache HTTP Server mod_ssl module
 incorrectly escaped certain data. A remote attacker could possibly
 use this issue to insert escape characters into log files.
 (CVE-2024-47252)

 Sven Hebrok, Felix Cramer, Tim Storm, Maximilian Radoy, and Juraj
 Somorovsky discovered that the Apache HTTP Server mod_ssl module
 incorrectly handled TLS 1.3 session resumption. A remote attacker
 could possibly use this issue to bypass access control. (CVE-2025-23048)

 Anthony CORSIEZ discovered that the Apache HTTP Server mod_proxy_http2
 module incorrectly handled missing host headers. A remote attacker
 could possibly use this issue to cause the server to crash, resulting
 in a denial of service. (CVE-2025-49630)

 Robert Merget discovered that the Apache HTTP Server mod_ssl module
 incorrectly handled TLS upgrades. A remote attacker could possibly
 use this issue to hijack an HTTP session. This update removes the
 old 'SSLEngine optional' configuration option, possibly requiring
 a configuration change in certain environments. (CVE-2025-49812)

 Gal Bar Nahum discovered that the Apache HTTP Server incorrectly
 handled certain memory operations. A remote attacker could possibly
 use this issue to cause the server to consume resources, leading
 to a denial of service. (CVE-2025-53020)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.18-2ubuntu3.17+esm16", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.29-1ubuntu4.27+esm6", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.23+esm2", rls:"UBUNTU20.04 LTS"))) {
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
