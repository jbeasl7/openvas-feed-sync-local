# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7665.1");
  script_cve_id("CVE-2025-37891", "CVE-2025-37894", "CVE-2025-37895", "CVE-2025-37896", "CVE-2025-37897", "CVE-2025-37898", "CVE-2025-37899", "CVE-2025-37900", "CVE-2025-37901", "CVE-2025-37903", "CVE-2025-37904", "CVE-2025-37905", "CVE-2025-37906", "CVE-2025-37907", "CVE-2025-37908", "CVE-2025-37909", "CVE-2025-37910", "CVE-2025-37911", "CVE-2025-37912", "CVE-2025-37913", "CVE-2025-37914", "CVE-2025-37915", "CVE-2025-37916", "CVE-2025-37917", "CVE-2025-37918", "CVE-2025-37919", "CVE-2025-37920", "CVE-2025-37921", "CVE-2025-37922", "CVE-2025-37923", "CVE-2025-37924", "CVE-2025-37926", "CVE-2025-37927", "CVE-2025-37928", "CVE-2025-37929", "CVE-2025-37930", "CVE-2025-37931", "CVE-2025-37933", "CVE-2025-37934", "CVE-2025-37935", "CVE-2025-37936", "CVE-2025-37946", "CVE-2025-37974", "CVE-2025-37990", "CVE-2025-37991", "CVE-2025-38216");
  script_tag(name:"creation_date", value:"2025-07-23 04:17:24 +0000 (Wed, 23 Jul 2025)");
  script_version("2025-07-23T05:44:57+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:57 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7665-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU25\.04");

  script_xref(name:"Advisory-ID", value:"USN-7665-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7665-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oracle' package(s) announced via the USN-7665-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PA-RISC architecture,
 - PowerPC architecture,
 - S390 architecture,
 - x86 architecture,
 - Compute Acceleration Framework,
 - Ublk userspace block driver,
 - Bluetooth drivers,
 - ARM SCMI message protocol,
 - GPU drivers,
 - IOMMU subsystem,
 - IRQ chip drivers,
 - Multiple devices driver,
 - Network drivers,
 - PCI subsystem,
 - PTP clock framework,
 - SPI subsystem,
 - BTRFS file system,
 - SMB network file system,
 - eXpress Data Path,
 - Universal MIDI packet (UMP) support module,
 - Tracing infrastructure,
 - Memory management,
 - IPv4 networking,
 - IPv6 networking,
 - Network traffic control,
 - AMD SoC Alsa drivers,
 - SoC Audio generic drivers,
(CVE-2025-37901, CVE-2025-37990, CVE-2025-37891, CVE-2025-37918,
CVE-2025-37930, CVE-2025-37909, CVE-2025-37906, CVE-2025-37913,
CVE-2025-37927, CVE-2025-37922, CVE-2025-37899, CVE-2025-37894,
CVE-2025-37934, CVE-2025-37911, CVE-2025-37912, CVE-2025-37933,
CVE-2025-37924, CVE-2025-37900, CVE-2025-37907, CVE-2025-37974,
CVE-2025-37928, CVE-2025-37914, CVE-2025-37905, CVE-2025-37921,
CVE-2025-37919, CVE-2025-37915, CVE-2025-37910, CVE-2025-37903,
CVE-2025-37936, CVE-2025-37904, CVE-2025-38216, CVE-2025-37923,
CVE-2025-37931, CVE-2025-37895, CVE-2025-37917, CVE-2025-37926,
CVE-2025-37916, CVE-2025-37935, CVE-2025-37898, CVE-2025-37897,
CVE-2025-37929, CVE-2025-37908, CVE-2025-37946, CVE-2025-37896,
CVE-2025-37920, CVE-2025-37991)");

  script_tag(name:"affected", value:"'linux-oracle' package(s) on Ubuntu 25.04.");

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

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1009-oracle", ver:"6.14.0-1009.9", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1009-oracle-64k", ver:"6.14.0-1009.9", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.14.0-1009.9", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.14", ver:"6.14.0-1009.9", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.14.0-1009.9", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.14", ver:"6.14.0-1009.9", rls:"UBUNTU25.04"))) {
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
