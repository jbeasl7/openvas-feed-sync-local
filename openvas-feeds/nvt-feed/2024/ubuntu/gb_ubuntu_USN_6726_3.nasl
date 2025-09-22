# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6726.3");
  script_cve_id("CVE-2023-46838", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52436", "CVE-2023-52438", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52444", "CVE-2023-52445", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52454", "CVE-2023-52457", "CVE-2023-52464", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52609", "CVE-2023-52612", "CVE-2024-0607", "CVE-2024-23851", "CVE-2024-26597", "CVE-2024-26633");
  script_tag(name:"creation_date", value:"2024-04-18 04:09:11 +0000 (Thu, 18 Apr 2024)");
  script_version("2025-02-28T05:38:48+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:48 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-27 03:23:29 +0000 (Thu, 27 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-6726-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6726-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6726-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-xilinx-zynqmp' package(s) announced via the USN-6726-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pratyush Yadav discovered that the Xen network backend implementation in
the Linux kernel did not properly handle zero length data request, leading
to a null pointer dereference vulnerability. An attacker in a guest VM
could possibly use this to cause a denial of service (host domain crash).
(CVE-2023-46838)

It was discovered that the IPv6 implementation of the Linux kernel did not
properly manage route cache memory usage. A remote attacker could use this
to cause a denial of service (memory exhaustion). (CVE-2023-52340)

It was discovered that the device mapper driver in the Linux kernel did not
properly validate target size during certain memory allocations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-52429, CVE-2024-23851)

Dan Carpenter discovered that the netfilter subsystem in the Linux kernel
did not store data in properly sized memory locations. A local user could
use this to cause a denial of service (system crash). (CVE-2024-0607)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Architecture specifics,
 - Cryptographic API,
 - Android drivers,
 - EDAC drivers,
 - GPU drivers,
 - Media drivers,
 - MTD block device drivers,
 - Network drivers,
 - NVME drivers,
 - TTY drivers,
 - Userspace I/O drivers,
 - F2FS file system,
 - GFS2 file system,
 - IPv6 Networking,
 - AppArmor security module,
(CVE-2023-52464, CVE-2023-52448, CVE-2023-52457, CVE-2023-52443,
CVE-2023-52439, CVE-2023-52612, CVE-2024-26633, CVE-2024-26597,
CVE-2023-52449, CVE-2023-52444, CVE-2023-52609, CVE-2023-52469,
CVE-2023-52445, CVE-2023-52451, CVE-2023-52470, CVE-2023-52454,
CVE-2023-52436, CVE-2023-52438)");

  script_tag(name:"affected", value:"'linux-xilinx-zynqmp' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1041-xilinx-zynqmp", ver:"5.4.0-1041.45", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1041.41", rls:"UBUNTU20.04 LTS"))) {
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
