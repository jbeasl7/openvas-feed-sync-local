# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844977");
  script_cve_id("CVE-2020-26558", "CVE-2020-27153", "CVE-2021-3588");
  script_tag(name:"creation_date", value:"2021-06-17 03:00:28 +0000 (Thu, 17 Jun 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 20:11:31 +0000 (Tue, 20 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|20\.10|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4989-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4989-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the USN-4989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BlueZ incorrectly checked certain permissions when
pairing. A local attacker could possibly use this issue to impersonate
devices. (CVE-2020-26558)

Jay LV discovered that BlueZ incorrectly handled redundant disconnect MGMT
events. A local attacker could use this issue to cause BlueZ to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-27153)

Ziming Zhang discovered that BlueZ incorrectly handled certain array
indexes. A local attacker could use this issue to cause BlueZ to crash,
resulting in a denial of service, or possibly obtain sensitive information.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 20.10. (CVE-2021-3588)");

  script_tag(name:"affected", value:"'bluez' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.48-0ubuntu3.5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.48-0ubuntu3.5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.53-0ubuntu3.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.53-0ubuntu3.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.55-0ubuntu1.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.55-0ubuntu1.2", rls:"UBUNTU20.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.56-0ubuntu4.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.56-0ubuntu4.1", rls:"UBUNTU21.04"))) {
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
