# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8154.1");
  script_cve_id("CVE-2026-33033", "CVE-2026-33034", "CVE-2026-3902", "CVE-2026-4277", "CVE-2026-4292");
  script_tag(name:"creation_date", value:"2026-04-08 04:50:57 +0000 (Wed, 08 Apr 2026)");
  script_version("2026-04-08T06:10:32+0000");
  script_tag(name:"last_modification", value:"2026-04-08 06:10:32 +0000 (Wed, 08 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8154-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8154-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8154-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-8154-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Seokchan Yoon discovered that Django incorrectly handled copying memory
when parsing multipart uploads with excessive whitespace. A remote attacker
could possibly use this issue to cause Django to use excessive resources,
leading to a denial of service. (CVE-2026-33033)

It was discovered that Django did not enforce an upload memory size limit
in the Content-Length header. A remote attacker could possibly use this
issue to cause Django to use excessive resources, leading to a denial of
service. This issue only affected Ubuntu 24.04 LTS and Ubuntu 25.10.
(CVE-2026-33034)

Tarek Nakkouch discovered that Django incorrectly handled underscores in
the ASGI headers. A remote attacker could possibly use this issue to spoof
HTTP headers. This issue only affected Ubuntu 22.04 LTS, Ubuntu 24.04 LTS,
and Ubuntu 25.10. (CVE-2026-3902)

It was discovered that Django incorrectly handled verification of model
data created with POST requests. A remote attacker could possibly use this
issue to forge new model permissions. (CVE-2026-4277, CVE-2026-4292)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.11.11-1ubuntu1.21+esm15", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.11.11-1ubuntu1.21+esm15", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"2:2.2.12-1ubuntu0.29+esm8", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"2:3.2.12-2ubuntu1.26", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"3:4.2.11-1ubuntu1.15", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"3:5.2.4-1ubuntu2.4", rls:"UBUNTU25.10"))) {
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
