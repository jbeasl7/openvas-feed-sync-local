# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7608.2");
  script_cve_id("CVE-2024-46787", "CVE-2024-50047", "CVE-2024-53051", "CVE-2025-37798", "CVE-2025-37890", "CVE-2025-37932", "CVE-2025-37997", "CVE-2025-38000", "CVE-2025-38001");
  script_tag(name:"creation_date", value:"2025-07-03 04:12:00 +0000 (Thu, 03 Jul 2025)");
  script_version("2025-07-03T05:42:53+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:53 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 22:16:21 +0000 (Wed, 23 Oct 2024)");

  script_name("Ubuntu: Security Advisory (USN-7608-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7608-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7608-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-fips, linux-fips, linux-gcp-fips' package(s) announced via the USN-7608-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - SMB network file system,
 - Memory management,
 - Netfilter,
 - Network traffic control,
(CVE-2025-37890, CVE-2024-46787, CVE-2025-37798, CVE-2025-38000,
CVE-2025-37932, CVE-2025-38001, CVE-2025-37997, CVE-2024-50047,
CVE-2024-53051)");

  script_tag(name:"affected", value:"'linux-aws-fips, linux-fips, linux-gcp-fips' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1086-gcp-fips", ver:"5.15.0-1086.95+fips1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1087-aws-fips", ver:"5.15.0-1087.94+fips1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-143-fips", ver:"5.15.0-143.153+fips1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-fips", ver:"5.15.0.1087.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-fips-5.15", ver:"5.15.0.1087.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-fips", ver:"5.15.0.143.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-fips-5.15", ver:"5.15.0.143.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-fips", ver:"5.15.0.1086.76", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-fips-5.15", ver:"5.15.0.1086.76", rls:"UBUNTU22.04 LTS"))) {
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
