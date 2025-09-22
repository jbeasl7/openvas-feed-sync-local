# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844194");
  script_cve_id("CVE-2019-0136", "CVE-2019-10207", "CVE-2019-13631", "CVE-2019-15090", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15223", "CVE-2019-15538", "CVE-2019-15925", "CVE-2019-15926", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2019-10-05 02:00:38 +0000 (Sat, 05 Oct 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-05 13:21:05 +0000 (Thu, 05 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-4147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4147-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4147-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-gke-5.0, linux-hwe, linux-kvm, linux-raspi2, linux-snapdragon' package(s) announced via the USN-4147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Intel Wi-Fi device driver in the Linux kernel
did not properly validate certain Tunneled Direct Link Setup (TDLS). A
physically proximate attacker could use this to cause a denial of service
(Wi-Fi disconnect). (CVE-2019-0136)

It was discovered that the Bluetooth UART implementation in the Linux
kernel did not properly check for missing tty operations. A local attacker
could use this to cause a denial of service. (CVE-2019-10207)

It was discovered that the GTCO tablet input driver in the Linux kernel did
not properly bounds check the initial HID report sent by the device. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-13631)

It was discovered that an out-of-bounds read existed in the QLogic QEDI
iSCSI Initiator Driver in the Linux kernel. A local attacker could possibly
use this to expose sensitive information (kernel memory). (CVE-2019-15090)

Hui Peng and Mathias Payer discovered that the USB audio driver for the
Linux kernel did not properly validate device meta data. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15117)

Hui Peng and Mathias Payer discovered that the USB audio driver for the
Linux kernel improperly performed recursion while handling device meta
data. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15118)

It was discovered that the Raremono AM/FM/SW radio device driver in the
Linux kernel did not properly allocate memory, leading to a use-after-free.
A physically proximate attacker could use this to cause a denial of service
or possibly execute arbitrary code. (CVE-2019-15211)

It was discovered at a double-free error existed in the USB Rio 500 device
driver for the Linux kernel. A physically proximate attacker could use this
to cause a denial of service. (CVE-2019-15212)

It was discovered that a race condition existed in the CPiA2 video4linux
device driver for the Linux kernel, leading to a use-after-free. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-15215)

It was discovered that a race condition existed in the Softmac USB Prism54
device driver in the Linux kernel. A physically proximate attacker could
use this to cause a denial of service (system crash). (CVE-2019-15220)

Benjamin Moody discovered that the XFS file system in the Linux kernel did
not properly handle an error condition when out of disk quota. A local
attacker could possibly use this to cause a denial of service.
(CVE-2019-15538)

It was discovered that the Hisilicon HNS3 ethernet device driver in the
Linux kernel contained an out of bounds access vulnerability. A local
attacker could use this to possibly cause a denial of service (system
crash). (CVE-2019-15925)

It ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-gke-5.0, linux-hwe, linux-kvm, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1020-gke", ver:"5.0.0-1020.20~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-31-generic", ver:"5.0.0-31.33~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-31-generic-lpae", ver:"5.0.0-31.33~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-31-lowlatency", ver:"5.0.0-31.33~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.0.0.31.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.0.0.31.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.0", ver:"5.0.0.1020.9", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.0.0.31.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.0.0.31.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.0.0.31.88", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1018-aws", ver:"5.0.0-1018.20", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1019-kvm", ver:"5.0.0-1019.20", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1019-raspi2", ver:"5.0.0-1019.19", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1020-gcp", ver:"5.0.0-1020.20", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1022-azure", ver:"5.0.0-1022.23", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1023-snapdragon", ver:"5.0.0-1023.24", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-31-generic", ver:"5.0.0-31.33", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-31-generic-lpae", ver:"5.0.0-31.33", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-31-lowlatency", ver:"5.0.0-31.33", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.0.0.1018.19", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.0.0.1022.21", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.0.0.1020.46", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.0.0.31.32", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.0.0.31.32", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.0.0.1020.46", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.0.0.1019.19", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.0.0.31.32", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.0.0.1019.16", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"5.0.0.1023.16", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.0.0.31.32", rls:"UBUNTU19.04"))) {
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
