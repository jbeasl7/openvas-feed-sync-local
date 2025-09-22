# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6701.2");
  script_cve_id("CVE-2023-2002", "CVE-2023-23000", "CVE-2023-3006", "CVE-2023-34256", "CVE-2023-39197", "CVE-2023-4132", "CVE-2023-46838", "CVE-2023-51781", "CVE-2023-6121", "CVE-2024-0775", "CVE-2024-1086", "CVE-2024-24855");
  script_tag(name:"creation_date", value:"2024-03-21 04:09:31 +0000 (Thu, 21 Mar 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-6701-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6701-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6701-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-gcp-4.15' package(s) announced via the USN-6701-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did
not properly perform permissions checks when handling HCI sockets. A
physically proximate attacker could use this to cause a denial of service
(bluetooth communication). (CVE-2023-2002)

It was discovered that the NVIDIA Tegra XUSB pad controller driver in the
Linux kernel did not properly handle return values in certain error
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-23000)

It was discovered that Spectre-BHB mitigations were missing for Ampere
processors. A local attacker could potentially use this to expose sensitive
information. (CVE-2023-3006)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly handle block device modification while it is
mounted. A privileged attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-34256)

Eric Dumazet discovered that the netfilter subsystem in the Linux kernel
did not properly handle DCCP conntrack buffers in certain situations,
leading to an out-of-bounds read vulnerability. An attacker could possibly
use this to expose sensitive information (kernel memory). (CVE-2023-39197)

It was discovered that the Siano USB MDTV receiver device driver in the
Linux kernel did not properly handle device initialization failures in
certain situations, leading to a use-after-free vulnerability. A physically
proximate attacker could use this cause a denial of service (system crash).
(CVE-2023-4132)

Pratyush Yadav discovered that the Xen network backend implementation in
the Linux kernel did not properly handle zero length data request, leading
to a null pointer dereference vulnerability. An attacker in a guest VM
could possibly use this to cause a denial of service (host domain crash).
(CVE-2023-46838)

It was discovered that a race condition existed in the AppleTalk networking
subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-51781)

Alon Zahavi discovered that the NVMe-oF/TCP subsystem of the Linux kernel
did not properly handle connect command payloads in certain situations,
leading to an out-of-bounds read vulnerability. A remote attacker could use
this to expose sensitive information (kernel memory). (CVE-2023-6121)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly handle the remount operation in certain cases,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2024-0775)

Notselwyn discovered that the netfilter subsystem in the Linux kernel did
not properly handle verdict parameters in certain cases, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gcp, linux-gcp-4.15' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1160-gcp", ver:"4.15.0-1160.177~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1160.150", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1160.150", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1160-gcp", ver:"4.15.0-1160.177", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1160.173", rls:"UBUNTU18.04 LTS"))) {
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
