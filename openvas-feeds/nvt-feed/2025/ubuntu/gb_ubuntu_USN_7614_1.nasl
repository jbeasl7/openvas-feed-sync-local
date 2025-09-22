# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7614.1");
  script_cve_id("CVE-2017-2661", "CVE-2018-1086", "CVE-2022-1049", "CVE-2022-2735");
  script_tag(name:"creation_date", value:"2025-07-04 04:09:47 +0000 (Fri, 04 Jul 2025)");
  script_version("2025-07-04T05:42:00+0000");
  script_tag(name:"last_modification", value:"2025-07-04 05:42:00 +0000 (Fri, 04 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-31 14:59:49 +0000 (Thu, 31 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-7614-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7614-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7614-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcs' package(s) announced via the USN-7614-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cedric Buissart discovered that pcs did not correctly handle certain
parameters. An attacker could possibly use this issue to leak sensitive
information or elevate their privileges. This issue only affected
Ubuntu 16.04 LTS. (CVE-2018-1086)

Ondrej Mular discovered that pcs did not correctly handle Unix socket
permissions. An attacker could possibly use this issue to elevate their
privileges. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-2735)

It was discovered that pcs did not correctly handle PAM authentication.
An attacker could possibly use this issue to bypass authentication
mechanisms. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2022-1049)

It was discovered that pcs did not correctly handle the validation of
Node names. An attacker could possibly use this issue to execute a
cross-site scripting (XSS) attack. This issue only affected
Ubuntu 16.04 LTS. (CVE-2017-2661)");

  script_tag(name:"affected", value:"'pcs' package(s) on Ubuntu 16.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"pcs", ver:"0.9.149-1ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pcs", ver:"0.10.4-3ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pcs", ver:"0.10.11-2ubuntu3+esm1", rls:"UBUNTU22.04 LTS"))) {
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
