# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7685.3");
  script_cve_id("CVE-2023-52757", "CVE-2023-52885", "CVE-2023-52975", "CVE-2024-38541", "CVE-2024-49883", "CVE-2024-49950", "CVE-2024-50073", "CVE-2024-53239", "CVE-2024-56748", "CVE-2025-37797");
  script_tag(name:"creation_date", value:"2025-08-06 04:22:01 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-03 15:18:12 +0000 (Mon, 03 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7685-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7685-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7685-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-fips, linux-azure-fips, linux-fips, linux-gcp-fips' package(s) announced via the USN-7685-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Device tree and open firmware driver,
 - SCSI subsystem,
 - TTY drivers,
 - Ext4 file system,
 - SMB network file system,
 - Bluetooth subsystem,
 - Network traffic control,
 - Sun RPC protocol,
 - USB sound devices,
(CVE-2023-52975, CVE-2024-56748, CVE-2023-52885, CVE-2025-37797,
CVE-2024-50073, CVE-2024-49950, CVE-2024-49883, CVE-2024-38541,
CVE-2023-52757, CVE-2024-53239)");

  script_tag(name:"affected", value:"'linux-aws-fips, linux-azure-fips, linux-fips, linux-gcp-fips' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1138-fips", ver:"4.15.0-1138.149", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-2084-gcp-fips", ver:"4.15.0-2084.90", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-2100-azure-fips", ver:"4.15.0-2100.106", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-2121-aws-fips", ver:"4.15.0-2121.127", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-fips", ver:"4.15.0.2121.115", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-fips-4.15", ver:"4.15.0.2121.115", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fips", ver:"4.15.0.2100.96", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fips-4.15", ver:"4.15.0.2100.96", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-fips", ver:"4.15.0.1138.135", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-fips", ver:"4.15.0.2084.82", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-fips-4.15", ver:"4.15.0.2084.82", rls:"UBUNTU18.04 LTS"))) {
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
