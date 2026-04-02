# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8098.3");
  script_cve_id("CVE-2021-47599", "CVE-2022-48875", "CVE-2022-49072", "CVE-2022-49267", "CVE-2024-49927", "CVE-2024-56640", "CVE-2025-21780", "CVE-2025-40215");
  script_tag(name:"creation_date", value:"2026-03-19 04:39:53 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-19T05:56:32+0000");
  script_tag(name:"last_modification", value:"2026-03-19 05:56:32 +0000 (Thu, 19 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-01 20:18:24 +0000 (Wed, 01 Oct 2025)");

  script_name("Ubuntu: Security Advisory (USN-8098-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8098-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8098-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2143853");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-aws-5.4, linux-gcp-5.4, linux-oracle, linux-oracle-5.4, linux-xilinx-zynqmp' package(s) announced via the USN-8098-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qualys discovered that several vulnerabilities existed in the AppArmor
Linux kernel Security Module (LSM). An unprivileged local attacker could
use these issues to load, replace, and remove arbitrary AppArmor profiles
causing denial of service, exposure of sensitive information (kernel
memory), local privilege escalation, or possibly escape a container.
(LP: #2143853)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - x86 architecture,
 - GPIO subsystem,
 - GPU drivers,
 - MMC subsystem,
 - BTRFS file system,
 - XFRM subsystem,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - SMC sockets,
(CVE-2021-47599, CVE-2022-48875, CVE-2022-49072, CVE-2022-49267,
CVE-2024-49927, CVE-2024-56640, CVE-2025-21780, CVE-2025-40215)");

  script_tag(name:"affected", value:"'linux-aws, linux-aws-5.4, linux-gcp-5.4, linux-oracle, linux-oracle-5.4, linux-xilinx-zynqmp' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1154-oracle", ver:"5.4.0-1154.164~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1156-aws", ver:"5.4.0-1156.166~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1159-gcp", ver:"5.4.0-1159.168~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.4.0.1156.166~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-5.4", ver:"5.4.0.1156.166~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1159.168~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-5.4", ver:"5.4.0.1159.168~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.4.0.1154.164~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.4", ver:"5.4.0.1154.164~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1074-xilinx-zynqmp", ver:"5.4.0-1074.78", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1154-oracle", ver:"5.4.0-1154.164", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1156-aws", ver:"5.4.0-1156.166", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-5.4", ver:"5.4.0.1156.153", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-20.04", ver:"5.4.0.1156.153", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.4", ver:"5.4.0.1154.148", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-20.04", ver:"5.4.0.1154.148", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1074.74", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp-5.4", ver:"5.4.0.1074.74", rls:"UBUNTU20.04 LTS"))) {
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
