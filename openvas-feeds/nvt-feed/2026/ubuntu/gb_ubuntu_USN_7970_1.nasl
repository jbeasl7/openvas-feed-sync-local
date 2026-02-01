# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7970.1");
  script_cve_id("CVE-2023-7250", "CVE-2024-26306", "CVE-2024-53580", "CVE-2025-54349", "CVE-2025-54350");
  script_tag(name:"creation_date", value:"2026-01-22 04:22:59 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-05 16:37:18 +0000 (Tue, 05 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7970-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7970-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7970-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iperf3' package(s) announced via the USN-7970-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jorge Sancho Larraz discovered that iperf3 did not properly manage certain
inputs, which could cause the server process to stop responding, waiting
for input on the control connection. A remote attacker could possibly use
this issue to cause a denial of service. This issue was only addressed in
Ubuntu 22.04 LTS. (CVE-2023-7250)

It was discovered that iperf3 had a timing side-channel when performing RSA
decryption. An attacker could possibly use this issue to recover sensitive
information. This issue was only addressed in Ubuntu 20.04 LTS and Ubuntu
22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-26306)

It was discovered that iperf3 incorrectly handled certain inputs. An
attacker could possibly use this issue to cause a denial of service. This
issue was only addressed in Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and Ubuntu
24.04 LTS. (CVE-2024-53580)

Han Lee discovered that iperf3 had an off-by-one heap overflow. An attacker
could possibly use this issue to crash the program or execute arbitrary
code. This issue was only addressed in Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2025-54349)

Han Lee discovered that iperf3 did not properly manage certain inputs. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2025-54350)");

  script_tag(name:"affected", value:"'iperf3' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"iperf3", ver:"3.7-3ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf0", ver:"3.7-3ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"iperf3", ver:"3.9-1+deb11u1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf0", ver:"3.9-1+deb11u1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"iperf3", ver:"3.16-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf0", ver:"3.16-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"iperf3", ver:"3.18-2ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libiperf0", ver:"3.18-2ubuntu0.1", rls:"UBUNTU25.10"))) {
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
