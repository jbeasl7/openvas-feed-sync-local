# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8032.1");
  script_cve_id("CVE-2025-69223", "CVE-2025-69224", "CVE-2025-69225", "CVE-2025-69226", "CVE-2025-69227", "CVE-2025-69228", "CVE-2025-69229");
  script_tag(name:"creation_date", value:"2026-02-17 04:37:15 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-17T05:57:49+0000");
  script_tag(name:"last_modification", value:"2026-02-17 05:57:49 +0000 (Tue, 17 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-14 19:17:21 +0000 (Wed, 14 Jan 2026)");

  script_name("Ubuntu: Security Advisory (USN-8032-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8032-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8032-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aiohttp' package(s) announced via the USN-8032-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Charles Chan discovered that AIOHTTP incorrectly handled the decompression
of compressed requests. A remote attacker could possibly use this issue to
cause a denial of service. This issue was only addressed in Ubuntu 25.10.
(CVE-2025-69223)

Thomas Rinsma discovered that AIOHTTP incorrectly handled non-ASCII
characters in HTTP headers. A remote attacker could possibly use this issue
to perform a request smuggling attack to bypass certain proxy protections.
This issue was only addressed in Ubuntu 22.04 LTS, Ubuntu 24.04 LTS and
Ubuntu 25.10. (CVE-2025-69224)

Thomas Rinsma discovered that AIOHTTP incorrectly handled non-ASCII
characters in the Range header. A remote attacker could possibly use this
issue to perform a request smuggling attack. (CVE-2025-69225)

Thomas Rinsma discovered that AIOHTTP incorrectly handled path
normalization when serving static files. A remote attacker could possibly
use this issue to obtain sensitive information. (CVE-2025-69226)

Thomas Rinsma discovered that AIOHTTP incorrectly handled certain POST
request bodies. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2025-69227)

Thomas Rinsma discovered that AIOHTTP incorrectly handled large POST
request payloads. A remote attacker could possibly use this issue to cause
a denial of service. (CVE-2025-69228)

It was discovered that AIOHTTP incorrectly handled chunked messages. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2025-69229)");

  script_tag(name:"affected", value:"'python-aiohttp' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.0.1-1ubuntu0.1~esm6", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.6.2-1ubuntu1+esm5", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.8.1-4ubuntu0.2+esm2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.9.1-1ubuntu0.1+esm2", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.11.16-1ubuntu0.1", rls:"UBUNTU25.10"))) {
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
