# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845243");
  script_cve_id("CVE-2021-3640", "CVE-2021-3752", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2022-02-17 07:17:35 +0000 (Thu, 17 Feb 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 19:47:28 +0000 (Mon, 28 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5267-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5267-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5267-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi, linux-raspi-5.4' package(s) announced via the USN-5267-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5267-1 fixed vulnerabilities in the Linux kernel. This update
provides the corresponding updates for the Linux kernel for Raspberry
Pi devices.

Original advisory details:

 It was discovered that the Bluetooth subsystem in the Linux kernel
 contained a use-after-free vulnerability. A local attacker could use this
 to cause a denial of service (system crash) or possibly execute arbitrary
 code. (CVE-2021-3640)

 Likang Luo discovered that a race condition existed in the Bluetooth
 subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
 local attacker could use this to cause a denial of service (system crash)
 or possibly execute arbitrary code. (CVE-2021-3752)

 Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel
 did not properly perform bounds checking in some situations. A local
 attacker could use this to cause a denial of service (system crash) or
 possibly execute arbitrary code. (CVE-2021-42739)");

  script_tag(name:"affected", value:"'linux-raspi, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1052-raspi", ver:"5.4.0-1052.58~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1052.54", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1052-raspi", ver:"5.4.0-1052.58", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1052.86", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1052.86", rls:"UBUNTU20.04 LTS"))) {
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
