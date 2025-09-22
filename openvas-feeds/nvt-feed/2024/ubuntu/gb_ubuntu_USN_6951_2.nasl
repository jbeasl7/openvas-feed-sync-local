# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6951.2");
  script_cve_id("CVE-2022-48674", "CVE-2022-48772", "CVE-2023-52434", "CVE-2023-52585", "CVE-2023-52752", "CVE-2023-52882", "CVE-2024-26886", "CVE-2024-27019", "CVE-2024-27398", "CVE-2024-27399", "CVE-2024-27401", "CVE-2024-31076", "CVE-2024-33621", "CVE-2024-35947", "CVE-2024-35976", "CVE-2024-36014", "CVE-2024-36015", "CVE-2024-36017", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-36902", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36919", "CVE-2024-36933", "CVE-2024-36934", "CVE-2024-36939", "CVE-2024-36940", "CVE-2024-36941", "CVE-2024-36946", "CVE-2024-36950", "CVE-2024-36954", "CVE-2024-36959", "CVE-2024-36960", "CVE-2024-36964", "CVE-2024-36971", "CVE-2024-37353", "CVE-2024-37356", "CVE-2024-38381", "CVE-2024-38549", "CVE-2024-38552", "CVE-2024-38558", "CVE-2024-38559", "CVE-2024-38560", "CVE-2024-38565", "CVE-2024-38567", "CVE-2024-38578", "CVE-2024-38579", "CVE-2024-38582", "CVE-2024-38583", "CVE-2024-38587", "CVE-2024-38589", "CVE-2024-38596", "CVE-2024-38598", "CVE-2024-38599", "CVE-2024-38600", "CVE-2024-38601", "CVE-2024-38607", "CVE-2024-38612", "CVE-2024-38613", "CVE-2024-38615", "CVE-2024-38618", "CVE-2024-38621", "CVE-2024-38627", "CVE-2024-38633", "CVE-2024-38634", "CVE-2024-38635", "CVE-2024-38637", "CVE-2024-38659", "CVE-2024-38661", "CVE-2024-38780", "CVE-2024-39276", "CVE-2024-39292", "CVE-2024-39301", "CVE-2024-39467", "CVE-2024-39471", "CVE-2024-39475", "CVE-2024-39480", "CVE-2024-39488", "CVE-2024-39489", "CVE-2024-39493");
  script_tag(name:"creation_date", value:"2024-08-15 04:08:17 +0000 (Thu, 15 Aug 2024)");
  script_version("2024-08-15T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-15 05:05:37 +0000 (Thu, 15 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-15 14:21:29 +0000 (Fri, 15 Mar 2024)");

  script_name("Ubuntu: Security Advisory (USN-6951-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6951-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6951-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-6951-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - M68K architecture,
 - User-Mode Linux (UML),
 - x86 architecture,
 - Accessibility subsystem,
 - Character device driver,
 - Clock framework and drivers,
 - CPU frequency scaling framework,
 - Hardware crypto device drivers,
 - Buffer Sharing and Synchronization framework,
 - FireWire subsystem,
 - GPU drivers,
 - HW tracing,
 - Macintosh device drivers,
 - Multiple devices driver,
 - Media drivers,
 - Network drivers,
 - Pin controllers subsystem,
 - S/390 drivers,
 - SCSI drivers,
 - SoundWire subsystem,
 - Greybus lights staging drivers,
 - TTY drivers,
 - Framebuffer layer,
 - Virtio drivers,
 - 9P distributed file system,
 - eCrypt file system,
 - EROFS file system,
 - Ext4 file system,
 - F2FS file system,
 - JFFS2 file system,
 - Network file system client,
 - NILFS2 file system,
 - SMB network file system,
 - Kernel debugger infrastructure,
 - IRQ subsystem,
 - Tracing infrastructure,
 - Dynamic debug library,
 - 9P file system network protocol,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Netfilter,
 - NET/ROM layer,
 - NFC subsystem,
 - NSH protocol,
 - Open vSwitch,
 - Phonet protocol,
 - TIPC protocol,
 - Unix domain sockets,
 - Wireless networking,
 - eXpress Data Path,
 - XFRM subsystem,
 - ALSA framework,
(CVE-2024-36934, CVE-2024-38578, CVE-2024-38600, CVE-2024-27399,
CVE-2024-39276, CVE-2024-38596, CVE-2024-36933, CVE-2024-36919,
CVE-2024-35976, CVE-2024-37356, CVE-2023-52585, CVE-2024-38558,
CVE-2024-38560, CVE-2024-38634, CVE-2024-36959, CVE-2024-38633,
CVE-2024-36886, CVE-2024-27398, CVE-2024-39493, CVE-2024-26886,
CVE-2024-31076, CVE-2024-38559, CVE-2024-38615, CVE-2024-36971,
CVE-2024-38627, CVE-2024-36964, CVE-2024-38780, CVE-2024-37353,
CVE-2024-38621, CVE-2024-36883, CVE-2024-39488, CVE-2024-38661,
CVE-2024-36939, CVE-2024-38589, CVE-2024-38565, CVE-2024-38381,
CVE-2024-35947, CVE-2024-36905, CVE-2022-48772, CVE-2024-36017,
CVE-2024-36946, CVE-2024-27401, CVE-2024-38579, CVE-2024-38612,
CVE-2024-38598, CVE-2024-38635, CVE-2024-38587, CVE-2024-38567,
CVE-2024-38549, CVE-2024-36960, CVE-2023-52752, CVE-2024-27019,
CVE-2024-38601, CVE-2024-39489, CVE-2024-39467, CVE-2023-52882,
CVE-2024-38583, CVE-2024-39480, CVE-2024-38607, CVE-2024-36940,
CVE-2024-38659, CVE-2023-52434, CVE-2024-36015, CVE-2024-38582,
CVE-2024-36950, CVE-2024-38552, CVE-2024-33621, CVE-2024-36954,
CVE-2024-39475, CVE-2024-39301, CVE-2024-38599, CVE-2024-36902,
CVE-2024-36286, CVE-2024-38613, CVE-2024-38637, CVE-2024-36941,
CVE-2024-36014, CVE-2024-38618, CVE-2024-36904, CVE-2024-36270,
CVE-2024-39292, CVE-2024-39471, CVE-2022-48674)");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1135-azure", ver:"5.4.0-1135.142", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-20.04", ver:"5.4.0.1135.129", rls:"UBUNTU20.04 LTS"))) {
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
