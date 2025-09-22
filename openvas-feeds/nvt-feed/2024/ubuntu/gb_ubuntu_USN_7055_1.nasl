# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7055.1");
  script_cve_id("CVE-2024-3596");
  script_tag(name:"creation_date", value:"2024-10-04 04:07:48 +0000 (Fri, 04 Oct 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-30 19:23:20 +0000 (Mon, 30 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-7055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7055-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7055-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius' package(s) announced via the USN-7055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Goldberg, Miro Haller, Nadia Heninger, Mike Milano, Dan Shumow, Marc
Stevens, and Adam Suhl discovered that FreeRADIUS incorrectly authenticated
certain responses. An attacker able to intercept communications between a
RADIUS client and server could possibly use this issue to forge responses,
bypass authentication, and access network devices and services.

This update introduces new configuration options called 'limit_proxy_state'
and 'require_message_authenticator' that default to 'auto' but should be
set to 'yes' once all RADIUS devices have been upgraded on a network.");

  script_tag(name:"affected", value:"'freeradius' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"3.0.20+dfsg-3ubuntu0.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"3.2.5+dfsg-3~ubuntu24.04.1", rls:"UBUNTU24.04 LTS"))) {
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
