# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7968.1");
  script_cve_id("CVE-2025-55753", "CVE-2025-58098", "CVE-2025-65082", "CVE-2025-66200");
  script_tag(name:"creation_date", value:"2026-01-20 08:35:13 +0000 (Tue, 20 Jan 2026)");
  script_version("2026-01-21T05:50:46+0000");
  script_tag(name:"last_modification", value:"2026-01-21 05:50:46 +0000 (Wed, 21 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7968-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7968-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7968-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-7968-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Apache HTTP Server incorrectly handled failed
ACME certificate renewals. This could result in renewal attempts to be
repeated without delays, possibly leading to a denial of service.
(CVE-2025-55753)

Anthony Parfenov discovered that the Apache HTTP Server would pass the
query string to cmd directives when configured with Server Side Includes
(SSI) enabled and mod_cgid. An attacker could possibly use this issue to
execute arbitrary code. (CVE-2025-58098)

Mattias Asander discovered that the Apache HTTP Server incorrectly
neutralized certain environment variables. This could result in
unexpectedly superseding variables calculated by the server for CGI
programs. (CVE-2025-65082)

Mattias Asander discovered that the Apache HTTP Server incorrectly
handled AllowOverride FileInfo configurations when using mod_userdir with
suexec. An attacker with access to use the RequestHeader directive in
htaccess can cause some CGI scripts to run under an unexpected userid.
(CVE-2025-66200)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.52-1ubuntu4.18", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.58-1ubuntu8.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.64-1ubuntu3.2", rls:"UBUNTU25.10"))) {
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
