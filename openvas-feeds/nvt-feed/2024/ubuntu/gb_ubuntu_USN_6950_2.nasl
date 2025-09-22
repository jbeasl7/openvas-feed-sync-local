# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6950.2");
  script_cve_id("CVE-2023-52585", "CVE-2023-52882", "CVE-2024-26900", "CVE-2024-26936", "CVE-2024-26980", "CVE-2024-27398", "CVE-2024-27399", "CVE-2024-27401", "CVE-2024-35848", "CVE-2024-35947", "CVE-2024-36017", "CVE-2024-36031", "CVE-2024-36880", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-36889", "CVE-2024-36897", "CVE-2024-36902", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36906", "CVE-2024-36916", "CVE-2024-36919", "CVE-2024-36928", "CVE-2024-36929", "CVE-2024-36931", "CVE-2024-36933", "CVE-2024-36934", "CVE-2024-36937", "CVE-2024-36938", "CVE-2024-36939", "CVE-2024-36940", "CVE-2024-36941", "CVE-2024-36944", "CVE-2024-36946", "CVE-2024-36947", "CVE-2024-36950", "CVE-2024-36952", "CVE-2024-36953", "CVE-2024-36954", "CVE-2024-36955", "CVE-2024-36957", "CVE-2024-36959", "CVE-2024-36960", "CVE-2024-36964", "CVE-2024-36965", "CVE-2024-36967", "CVE-2024-36969", "CVE-2024-36975", "CVE-2024-38600");
  script_tag(name:"creation_date", value:"2024-08-13 04:08:36 +0000 (Tue, 13 Aug 2024)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-10 18:29:29 +0000 (Fri, 10 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6950-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6950-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6950-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-5.15, linux-gkeop-5.15, linux-ibm, linux-ibm-5.15, linux-raspi' package(s) announced via the USN-6950-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - ARM64 architecture,
 - Block layer subsystem,
 - Bluetooth drivers,
 - Clock framework and drivers,
 - FireWire subsystem,
 - GPU drivers,
 - InfiniBand drivers,
 - Multiple devices driver,
 - EEPROM drivers,
 - Network drivers,
 - Pin controllers subsystem,
 - Remote Processor subsystem,
 - S/390 drivers,
 - SCSI drivers,
 - 9P distributed file system,
 - Network file system client,
 - SMB network file system,
 - Socket messages infrastructure,
 - Dynamic debug library,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Multipath TCP,
 - NSH protocol,
 - Phonet protocol,
 - TIPC protocol,
 - Wireless networking,
 - Key management,
 - ALSA framework,
 - HD-audio driver,
(CVE-2024-36883, CVE-2024-36940, CVE-2024-36902, CVE-2024-36975,
CVE-2024-36964, CVE-2024-36938, CVE-2024-36931, CVE-2024-35848,
CVE-2024-26900, CVE-2024-36967, CVE-2024-36904, CVE-2024-27398,
CVE-2024-36031, CVE-2023-52585, CVE-2024-36886, CVE-2024-36937,
CVE-2024-36954, CVE-2024-36916, CVE-2024-36905, CVE-2024-36959,
CVE-2024-26980, CVE-2024-26936, CVE-2024-36928, CVE-2024-36889,
CVE-2024-36929, CVE-2024-36933, CVE-2024-27399, CVE-2024-36946,
CVE-2024-36906, CVE-2024-36965, CVE-2024-36957, CVE-2024-36941,
CVE-2024-36897, CVE-2024-36952, CVE-2024-36947, CVE-2024-36950,
CVE-2024-36880, CVE-2024-36017, CVE-2023-52882, CVE-2024-36969,
CVE-2024-38600, CVE-2024-36955, CVE-2024-36960, CVE-2024-27401,
CVE-2024-36919, CVE-2024-36934, CVE-2024-35947, CVE-2024-36953,
CVE-2024-36944, CVE-2024-36939)");

  script_tag(name:"affected", value:"'linux-aws-5.15, linux-gkeop-5.15, linux-ibm, linux-ibm-5.15, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1050-gkeop", ver:"5.15.0-1050.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1060-ibm", ver:"5.15.0-1060.63~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1067-aws", ver:"5.15.0-1067.73~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.15.0.1067.73~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1050.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1060.63~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1060-ibm", ver:"5.15.0-1060.63", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1060-raspi", ver:"5.15.0-1060.63", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1060.56", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1060.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1060.58", rls:"UBUNTU22.04 LTS"))) {
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
