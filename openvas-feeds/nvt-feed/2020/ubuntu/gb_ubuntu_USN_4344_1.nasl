# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844409");
  script_cve_id("CVE-2019-16234", "CVE-2019-19051", "CVE-2019-19768", "CVE-2020-10942", "CVE-2020-8648", "CVE-2020-8992", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2020-04-29 03:01:05 +0000 (Wed, 29 Apr 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-28 17:54:59 +0000 (Tue, 28 Apr 2020)");

  script_name("Ubuntu: Security Advisory (USN-4344-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4344-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4344-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke-5.0, linux-oem-osp1' package(s) announced via the USN-4344-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Intel Wi-Fi driver in the Linux kernel did not
properly check for errors in some situations. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2019-16234)

It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did
not properly deallocate memory in certain situations. A local attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19051)

Tristan Madani discovered that the block I/O tracing implementation in the
Linux kernel contained a race condition. A local attacker could use this to
cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2019-19768)

It was discovered that the vhost net driver in the Linux kernel contained a
stack buffer overflow. A local attacker with the ability to perform ioctl()
calls on /dev/vhost-net could use this to cause a denial of service (system
crash). (CVE-2020-10942)

It was discovered that the virtual terminal implementation in the Linux
kernel contained a race condition. A local attacker could possibly use this
to cause a denial of service (system crash) or expose sensitive
information. (CVE-2020-8648)

Shijie Luo discovered that the ext4 file system implementation in the Linux
kernel did not properly check for a too-large journal size. An attacker
could use this to construct a malicious ext4 image that, when mounted,
could cause a denial of service (soft lockup). (CVE-2020-8992)

Jordy Zomer discovered that the floppy driver in the Linux kernel did not
properly check for errors in some situations. A local attacker could
possibly use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2020-9383)");

  script_tag(name:"affected", value:"'linux-gke-5.0, linux-oem-osp1' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1035-gke", ver:"5.0.0-1035.36", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1050-oem-osp1", ver:"5.0.0-1050.55", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.0", ver:"5.0.0.1035.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.0.0.1050.53", rls:"UBUNTU18.04 LTS"))) {
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
