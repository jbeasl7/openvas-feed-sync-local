# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6739.1");
  script_cve_id("CVE-2019-25162", "CVE-2021-46936", "CVE-2021-46955", "CVE-2021-46966", "CVE-2021-46990", "CVE-2022-20422", "CVE-2023-1382", "CVE-2023-1998", "CVE-2023-24023", "CVE-2023-51043", "CVE-2023-51779", "CVE-2023-52429", "CVE-2023-52445", "CVE-2023-52451", "CVE-2023-52600", "CVE-2023-52603", "CVE-2024-23851");
  script_tag(name:"creation_date", value:"2024-04-22 04:09:21 +0000 (Mon, 22 Apr 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-12 17:36:57 +0000 (Thu, 12 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-6739-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6739-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6739-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-6739-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the instruction emulator
of the Linux kernel on Arm 64-bit systems. A local attacker could use this
to cause a denial of service (system crash). (CVE-2022-20422)

Wei Chen discovered that a race condition existed in the TIPC protocol
implementation in the Linux kernel, leading to a null pointer dereference
vulnerability. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-1382)

Jose Oliveira and Rodrigo Branco discovered that the Spectre Variant 2
mitigations with prctl syscall were insufficient in some situations. A
local attacker could possibly use this to expose sensitive information.
(CVE-2023-1998)

Daniele Antonioli discovered that the Secure Simple Pairing and Secure
Connections pairing in the Bluetooth protocol could allow an
unauthenticated user to complete authentication without pairing
credentials. A physically proximate attacker placed between two Bluetooth
devices could use this to subsequently impersonate one of the paired
devices. (CVE-2023-24023)

shanzhulig discovered that the DRM subsystem in the Linux kernel contained
a race condition when performing certain operation while handling driver
unload, leading to a use-after-free vulnerability. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-51043)

It was discovered that a race condition existed in the Bluetooth subsystem
of the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-51779)

It was discovered that the device mapper driver in the Linux kernel did not
properly validate target size during certain memory allocations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-52429, CVE-2024-23851)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Architecture specifics,
 - ACPI drivers,
 - I2C subsystem,
 - Media drivers,
 - JFS file system,
 - IPv4 Networking,
 - Open vSwitch,
(CVE-2021-46966, CVE-2021-46936, CVE-2023-52451, CVE-2019-25162,
CVE-2023-52445, CVE-2023-52600, CVE-2021-46990, CVE-2021-46955,
CVE-2023-52603)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1130-aws", ver:"4.4.0-1130.136", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-253-generic", ver:"4.4.0-253.287~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-253-lowlatency", ver:"4.4.0-253.287~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1130.127", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.253.287~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.253.287~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.253.287~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1131-kvm", ver:"4.4.0-1131.141", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1168-aws", ver:"4.4.0-1168.183", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-253-generic", ver:"4.4.0-253.287", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-253-lowlatency", ver:"4.4.0-253.287", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1168.172", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.253.259", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.253.259", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1131.128", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.253.259", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.253.259", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.253.259", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.253.259", rls:"UBUNTU16.04 LTS"))) {
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
