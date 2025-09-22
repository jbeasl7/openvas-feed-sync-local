# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7021.4");
  script_cve_id("CVE-2024-26677", "CVE-2024-27012", "CVE-2024-38570", "CVE-2024-39494", "CVE-2024-39496", "CVE-2024-41009", "CVE-2024-42160", "CVE-2024-42228");
  script_tag(name:"creation_date", value:"2024-10-04 04:07:48 +0000 (Fri, 04 Oct 2024)");
  script_version("2024-10-04T15:39:55+0000");
  script_tag(name:"last_modification", value:"2024-10-04 15:39:55 +0000 (Fri, 04 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-02 14:29:26 +0000 (Fri, 02 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-7021-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7021-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7021-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-fde-5.15' package(s) announced via the USN-7021-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - BTRFS file system,
 - F2FS file system,
 - GFS2 file system,
 - BPF subsystem,
 - Netfilter,
 - RxRPC session sockets,
 - Integrity Measurement Architecture(IMA) framework,
(CVE-2024-41009, CVE-2024-26677, CVE-2024-42160, CVE-2024-39494,
CVE-2024-39496, CVE-2024-38570, CVE-2024-27012, CVE-2024-42228)");

  script_tag(name:"affected", value:"'linux-azure-fde-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1073-azure-fde", ver:"5.15.0-1073.82~20.04.1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.15.0.1073.82~20.04.1.50", rls:"UBUNTU20.04 LTS"))) {
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
