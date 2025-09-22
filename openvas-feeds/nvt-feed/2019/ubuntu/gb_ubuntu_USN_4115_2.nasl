# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844174");
  script_cve_id("CVE-2018-19985", "CVE-2018-20784", "CVE-2019-0136", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11487", "CVE-2019-11599", "CVE-2019-11810", "CVE-2019-13631");
  script_tag(name:"creation_date", value:"2019-09-12 02:01:51 +0000 (Thu, 12 Sep 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 18:42:14 +0000 (Tue, 07 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-4115-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4115-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4115-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1842447");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-oracle, linux-raspi2' package(s) announced via the USN-4115-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN 4115-1 fixed vulnerabilities in the Linux 4.15 kernel for Ubuntu
18.04 LTS and Ubuntu 16.04 LTS. Unfortunately, as part of the update,
a regression was introduced that caused a kernel crash when handling
fragmented packets in some situations. This update addresses the issue.

We apologize for the inconvenience.

Original advisory details:

 Hui Peng and Mathias Payer discovered that the Option USB High Speed driver
 in the Linux kernel did not properly validate metadata received from the
 device. A physically proximate attacker could use this to cause a denial of
 service (system crash). (CVE-2018-19985)

 Zhipeng Xie discovered that an infinite loop could triggered in the CFS
 Linux kernel process scheduler. A local attacker could possibly use this to
 cause a denial of service. (CVE-2018-20784)

 It was discovered that the Intel Wi-Fi device driver in the Linux kernel did
 not properly validate certain Tunneled Direct Link Setup (TDLS). A
 physically proximate attacker could use this to cause a denial of service
 (Wi-Fi disconnect). (CVE-2019-0136)

 It was discovered that the Bluetooth UART implementation in the Linux
 kernel did not properly check for missing tty operations. A local attacker
 could use this to cause a denial of service. (CVE-2019-10207)

 Amit Klein and Benny Pinkas discovered that the Linux kernel did not
 sufficiently randomize IP ID values generated for connectionless networking
 protocols. A remote attacker could use this to track particular Linux
 devices. (CVE-2019-10638)

 Amit Klein and Benny Pinkas discovered that the location of kernel
 addresses could be exposed by the implementation of connection-less network
 protocols in the Linux kernel. A remote attacker could possibly use this to
 assist in the exploitation of another vulnerability in the Linux kernel.
 (CVE-2019-10639)

 It was discovered that an integer overflow existed in the Linux kernel when
 reference counting pages, leading to potential use-after-free issues. A
 local attacker could use this to cause a denial of service (system crash)
 or possibly execute arbitrary code. (CVE-2019-11487)

 Jann Horn discovered that a race condition existed in the Linux kernel when
 performing core dumps. A local attacker could use this to cause a denial of
 service (system crash) or expose sensitive information. (CVE-2019-11599)

 It was discovered that a null pointer dereference vulnerability existed in
 the LSI Logic MegaRAID driver in the Linux kernel. A local attacker could
 use this to cause a denial of service (system crash). (CVE-2019-11810)

 It was discovered that the GTCO tablet input driver in the Linux kernel did
 not properly bounds check the initial HID report sent by the device. A
 physically proximate attacker could use this to cause a denial of service
 (system crash) or possibly execute arbitrary code. (CVE-2019-13631)

 Praveen Pandey discovered that the Linux kernel did ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-oracle, linux-raspi2' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1023-oracle", ver:"4.15.0-1023.26~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1042-gcp", ver:"4.15.0-1042.44", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1048-aws", ver:"4.15.0-1048.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1057-azure", ver:"4.15.0-1057.62", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-62-generic", ver:"4.15.0-62.69~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-62-generic-lpae", ver:"4.15.0-62.69~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-62-lowlatency", ver:"4.15.0-62.69~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1048.48", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1057.60", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1042.56", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.62.82", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.15.0.62.82", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1042.56", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.62.82", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.62.82", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1023.17", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.62.82", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1023-oracle", ver:"4.15.0-1023.26", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1042-gke", ver:"4.15.0-1042.44", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1044-kvm", ver:"4.15.0-1044.44", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1045-raspi2", ver:"4.15.0-1045.49", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1048-aws", ver:"4.15.0-1048.50", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-62-generic", ver:"4.15.0-62.69", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-62-generic-lpae", ver:"4.15.0-62.69", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-62-lowlatency", ver:"4.15.0-62.69", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.15.0.1048.47", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.62.64", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.15.0.62.64", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1042.45", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-4.15", ver:"4.15.0.1042.45", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.15.0.1044.44", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.62.64", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1023.26", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.15.0.1045.43", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.15.0.62.64", rls:"UBUNTU18.04 LTS"))) {
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
