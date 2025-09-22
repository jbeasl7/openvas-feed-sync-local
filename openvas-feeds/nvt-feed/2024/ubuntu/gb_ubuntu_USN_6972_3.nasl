# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6972.3");
  script_cve_id("CVE-2023-52470", "CVE-2023-52629", "CVE-2023-52644", "CVE-2023-52760", "CVE-2023-52806", "CVE-2024-22099", "CVE-2024-24860", "CVE-2024-26600", "CVE-2024-26654", "CVE-2024-26679", "CVE-2024-26687", "CVE-2024-26903", "CVE-2024-35835", "CVE-2024-35955", "CVE-2024-36901", "CVE-2024-36940", "CVE-2024-39292", "CVE-2024-39484");
  script_tag(name:"creation_date", value:"2024-08-26 04:08:57 +0000 (Mon, 26 Aug 2024)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-10 18:29:29 +0000 (Fri, 10 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6972-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6972-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6972-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-4.15' package(s) announced via the USN-6972-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux
Kernel contained a race condition, leading to a NULL pointer dereference.
An attacker could possibly use this to cause a denial of service (system
crash). (CVE-2024-22099)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a null pointer dereference vulnerability. A
privileged local attacker could use this to possibly cause a denial of
service (system crash). (CVE-2024-24860)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - SuperH RISC architecture,
 - User-Mode Linux (UML),
 - GPU drivers,
 - MMC subsystem,
 - Network drivers,
 - PHY drivers,
 - Pin controllers subsystem,
 - Xen hypervisor drivers,
 - GFS2 file system,
 - Core kernel,
 - Bluetooth subsystem,
 - IPv4 networking,
 - IPv6 networking,
 - HD-audio driver,
 - ALSA SH drivers,
(CVE-2024-26903, CVE-2024-35835, CVE-2023-52644, CVE-2024-39292,
CVE-2024-36940, CVE-2024-26600, CVE-2023-52629, CVE-2024-35955,
CVE-2023-52760, CVE-2023-52806, CVE-2024-39484, CVE-2024-26679,
CVE-2024-26654, CVE-2024-36901, CVE-2024-26687, CVE-2023-52470)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-4.15' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1180-azure", ver:"4.15.0-1180.195~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1180.195~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1180-azure", ver:"4.15.0-1180.195~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1180.195~16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1180-azure", ver:"4.15.0-1180.195", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1180.148", rls:"UBUNTU18.04 LTS"))) {
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
