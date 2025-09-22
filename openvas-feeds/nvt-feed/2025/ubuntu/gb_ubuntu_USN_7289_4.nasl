# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7289.4");
  script_cve_id("CVE-2023-52913", "CVE-2024-26718", "CVE-2024-35887", "CVE-2024-39497", "CVE-2024-40953", "CVE-2024-40965", "CVE-2024-41066", "CVE-2024-41080", "CVE-2024-42252", "CVE-2024-42291", "CVE-2024-50010", "CVE-2024-50036", "CVE-2024-50058", "CVE-2024-50072", "CVE-2024-50074", "CVE-2024-50082", "CVE-2024-50083", "CVE-2024-50085", "CVE-2024-50086", "CVE-2024-50099", "CVE-2024-50101", "CVE-2024-50103", "CVE-2024-50110", "CVE-2024-50115", "CVE-2024-50116", "CVE-2024-50117", "CVE-2024-50127", "CVE-2024-50128", "CVE-2024-50131", "CVE-2024-50134", "CVE-2024-50141", "CVE-2024-50142", "CVE-2024-50143", "CVE-2024-50148", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50153", "CVE-2024-50154", "CVE-2024-50156", "CVE-2024-50160", "CVE-2024-50162", "CVE-2024-50163", "CVE-2024-50167", "CVE-2024-50168", "CVE-2024-50171", "CVE-2024-50182", "CVE-2024-50185", "CVE-2024-50192", "CVE-2024-50193", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50196", "CVE-2024-50198", "CVE-2024-50199", "CVE-2024-50201", "CVE-2024-50202", "CVE-2024-50205", "CVE-2024-50208", "CVE-2024-50209", "CVE-2024-50218", "CVE-2024-50229", "CVE-2024-50230", "CVE-2024-50232", "CVE-2024-50233", "CVE-2024-50234", "CVE-2024-50236", "CVE-2024-50237", "CVE-2024-50244", "CVE-2024-50245", "CVE-2024-50247", "CVE-2024-50249", "CVE-2024-50251", "CVE-2024-50257", "CVE-2024-50259", "CVE-2024-50262", "CVE-2024-50265", "CVE-2024-50267", "CVE-2024-50268", "CVE-2024-50269", "CVE-2024-50273", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50282", "CVE-2024-50287", "CVE-2024-50290", "CVE-2024-50292", "CVE-2024-50295", "CVE-2024-50296", "CVE-2024-50299", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53042", "CVE-2024-53052", "CVE-2024-53055", "CVE-2024-53058", "CVE-2024-53059", "CVE-2024-53061", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53088", "CVE-2024-53097", "CVE-2024-53101", "CVE-2024-53104");
  script_tag(name:"creation_date", value:"2025-02-28 04:04:00 +0000 (Fri, 28 Feb 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 20:34:45 +0000 (Wed, 05 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7289-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7289-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7289-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg, linux-intel-iotg-5.15' package(s) announced via the USN-7289-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - x86 architecture,
 - Block layer subsystem,
 - ACPI drivers,
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - IRQ chip drivers,
 - Multiple devices driver,
 - Media drivers,
 - Network drivers,
 - STMicroelectronics network drivers,
 - Parport drivers,
 - Pin controllers subsystem,
 - Direct Digital Synthesis drivers,
 - TCM subsystem,
 - TTY drivers,
 - USB Dual Role (OTG-ready) Controller drivers,
 - USB Serial drivers,
 - USB Type-C support driver,
 - USB Type-C Connector System Software Interface driver,
 - BTRFS file system,
 - File systems infrastructure,
 - Network file system (NFS) client,
 - NILFS2 file system,
 - NTFS3 file system,
 - SMB network file system,
 - User-space API (UAPI),
 - io_uring subsystem,
 - BPF subsystem,
 - Timer substystem drivers,
 - Tracing infrastructure,
 - Closures library,
 - Memory management,
 - Amateur Radio drivers,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netfilter,
 - Network traffic control,
 - SCTP protocol,
 - XFRM subsystem,
 - Key management,
 - FireWire sound drivers,
 - HD-audio driver,
 - QCOM ASoC drivers,
 - STMicroelectronics SoC drivers,
 - KVM core,
(CVE-2024-50082, CVE-2024-50134, CVE-2024-50142, CVE-2023-52913,
CVE-2024-50205, CVE-2024-50127, CVE-2024-50208, CVE-2024-50143,
CVE-2024-50163, CVE-2024-53059, CVE-2024-50282, CVE-2024-50279,
CVE-2024-50296, CVE-2024-50295, CVE-2024-50010, CVE-2024-53088,
CVE-2024-50128, CVE-2024-50290, CVE-2024-50099, CVE-2024-50234,
CVE-2024-50154, CVE-2024-53052, CVE-2024-50116, CVE-2024-50168,
CVE-2024-50086, CVE-2024-50267, CVE-2024-50156, CVE-2024-50110,
CVE-2024-50103, CVE-2024-50192, CVE-2024-40953, CVE-2024-50085,
CVE-2024-50247, CVE-2024-50257, CVE-2024-50237, CVE-2024-50185,
CVE-2024-50198, CVE-2024-50229, CVE-2024-50171, CVE-2024-50259,
CVE-2024-50209, CVE-2024-50233, CVE-2024-35887, CVE-2024-50251,
CVE-2024-50141, CVE-2024-53061, CVE-2024-50232, CVE-2024-50167,
CVE-2024-50201, CVE-2024-50193, CVE-2024-50269, CVE-2024-39497,
CVE-2024-50036, CVE-2024-50299, CVE-2024-50072, CVE-2024-53101,
CVE-2024-50262, CVE-2024-50194, CVE-2024-50202, CVE-2024-50101,
CVE-2024-50151, CVE-2024-41080, CVE-2024-42291, CVE-2024-50245,
CVE-2024-50278, CVE-2024-50195, CVE-2024-50265, CVE-2024-50074,
CVE-2024-53063, CVE-2024-50131, CVE-2024-53058, CVE-2024-50160,
CVE-2024-50287, CVE-2024-40965, CVE-2024-50273, CVE-2024-50268,
CVE-2024-50302, CVE-2024-50218, CVE-2024-50199, CVE-2024-50196,
CVE-2024-50083, CVE-2024-50244, CVE-2024-50117, CVE-2024-50058,
CVE-2024-53055, CVE-2024-50182, CVE-2024-53097, CVE-2024-50236,
CVE-2024-50162, CVE-2024-50301, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-intel-iotg, linux-intel-iotg-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1073-intel-iotg", ver:"5.15.0-1073.79~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel", ver:"5.15.0.1073.79~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1073.79~20.04.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1073-intel-iotg", ver:"5.15.0-1073.79", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1073.73", rls:"UBUNTU22.04 LTS"))) {
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
