# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844257");
  script_cve_id("CVE-2019-15794", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-18810", "CVE-2019-19048", "CVE-2019-19060", "CVE-2019-19061", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19069", "CVE-2019-19075", "CVE-2019-19083");
  script_tag(name:"creation_date", value:"2019-12-04 03:01:45 +0000 (Wed, 04 Dec 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-19 14:12:49 +0000 (Tue, 19 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-4208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4208-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4208-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-gcp-5.3, linux-kvm, linux-oracle' package(s) announced via the USN-4208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the OverlayFS and ShiftFS Drivers in the Linux
kernel did not properly handle reference counting during memory mapping
operations when used in conjunction with AUFS. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-15794)

Nicolas Waisman discovered that the WiFi driver stack in the Linux kernel
did not properly validate SSID lengths. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-17133)

It was discovered that the ARM Komeda display driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-18810)

It was discovered that the VirtualBox guest driver implementation in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2019-19048)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19060, CVE-2019-19061)

It was discovered that the Intel OPA Gen1 Infiniband Driver for the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19065)

It was discovered that the AMD Audio Coprocessor driver for the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker with the ability to load modules could use this to cause a
denial of service (memory exhaustion). (CVE-2019-19067)

It was discovered in the Qualcomm FastRPC Driver for the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19069)

It was discovered that the Cascoda CA8210 SPI 802.15.4 wireless controller
driver for the Linux kernel did not properly deallocate memory in certain
error conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19075)

It was discovered that the AMD Display Engine Driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attack could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19083)

Nicolas Waisman discovered that the Chelsio T4/T5 RDMA Driver for the Linux
kernel performed DMA from a kernel stack. A local attacker could use this
to cause a denial of service (system crash). (CVE-2019-17075)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-gcp-5.3, linux-kvm, linux-oracle' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1009-gcp", ver:"5.3.0-1009.10~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-edge", ver:"5.3.0.1009.9", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1007-oracle", ver:"5.3.0-1007.8", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1008-aws", ver:"5.3.0-1008.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1008-kvm", ver:"5.3.0-1008.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1009-gcp", ver:"5.3.0-1009.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-24-generic", ver:"5.3.0-24.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-24-generic-lpae", ver:"5.3.0-24.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-24-lowlatency", ver:"5.3.0-24.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-24-snapdragon", ver:"5.3.0-24.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.3.0.1008.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.3.0.1009.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.3.0.24.28", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.3.0.24.28", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.3.0.1009.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.3.0.1008.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.3.0.24.28", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.3.0.1007.8", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"5.3.0.24.28", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.3.0.24.28", rls:"UBUNTU19.10"))) {
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
