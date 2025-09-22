# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7022.3");
  script_cve_id("CVE-2021-47188", "CVE-2022-48791", "CVE-2022-48863", "CVE-2024-26677", "CVE-2024-26787", "CVE-2024-27012", "CVE-2024-38570", "CVE-2024-39494", "CVE-2024-42160", "CVE-2024-42228");
  script_tag(name:"creation_date", value:"2024-10-10 14:30:54 +0000 (Thu, 10 Oct 2024)");
  script_version("2024-10-11T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-10-11 05:05:54 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-02 14:29:26 +0000 (Fri, 02 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-7022-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7022-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7022-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi-5.4' package(s) announced via the USN-7022-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - Modular ISDN driver,
 - MMC subsystem,
 - SCSI drivers,
 - F2FS file system,
 - GFS2 file system,
 - Netfilter,
 - RxRPC session sockets,
 - Integrity Measurement Architecture(IMA) framework,
(CVE-2021-47188, CVE-2024-39494, CVE-2022-48791, CVE-2022-48863,
CVE-2024-42228, CVE-2024-38570, CVE-2024-42160, CVE-2024-26787,
CVE-2024-27012, CVE-2024-26677)");

  script_tag(name:"affected", value:"'linux-raspi-5.4' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1117-raspi", ver:"5.4.0-1117.129~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1117.129~18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
