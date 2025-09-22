# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7639.1");
  script_cve_id("CVE-2024-42516", "CVE-2024-43204", "CVE-2024-47252", "CVE-2025-23048", "CVE-2025-49630", "CVE-2025-49812", "CVE-2025-53020");
  script_tag(name:"creation_date", value:"2025-07-18 04:17:04 +0000 (Fri, 18 Jul 2025)");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7639-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7639-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-7639-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Apache HTTP Server incorrectly handled certain
Content-Type response headers. A remote attacker could possibly use this
issue to perform HTTP response splitting attacks. (CVE-2024-42516)

xiaojunjie discovered that the Apache HTTP Server mod_proxy module
incorrectly handled certain requests. A remote attacker could possibly use
this issue to send outbound proxy requests to an arbitrary URL.
(CVE-2024-43204)

John Runyon discovered that the Apache HTTP Server mod_ssl module
incorrectly escaped certain data. A remote attacker could possibly use this
issue to insert escape characters into log files. (CVE-2024-47252)

Sven Hebrok, Felix Cramer, Tim Storm, Maximilian Radoy, and Juraj
Somorovsky discovered that the Apache HTTP Server mod_ssl module
incorrectly handled TLS 1.3 session resumption. A remote attacker could
possibly use this issue to bypass access control. (CVE-2025-23048)

Anthony CORSIEZ discovered that the Apache HTTP Server mod_proxy_http2
module incorrectly handled missing host headers. A remote attacker could
possibly use this issue to cause the server to crash, resulting in a denial
of service. (CVE-2025-49630)

Robert Merget discovered that the Apache HTTP Server mod_ssl module
incorrectly handled TLS upgrades. A remote attacker could possibly use this
issue to hijack an HTTP session. This update removes the old 'SSLEngine
optional' configuration option, possibly requiring a configuration change
in certain environments. (CVE-2025-49812)

Gal Bar Nahum discovered that the Apache HTTP Server incorrectly handled
certain memory operations. A remote attacker could possibly use this
issue to cause the server to consume resources, leading to a denial of
service. (CVE-2025-53020)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.52-1ubuntu4.15", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.58-1ubuntu8.7", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.63-1ubuntu1.1", rls:"UBUNTU25.04"))) {
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
