# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843554");
  script_cve_id("CVE-2018-1068", "CVE-2018-1092", "CVE-2018-7492", "CVE-2018-8087", "CVE-2018-8781");
  script_tag(name:"creation_date", value:"2018-06-12 03:55:36 +0000 (Tue, 12 Jun 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-06 17:29:56 +0000 (Wed, 06 Jun 2018)");

  script_name("Ubuntu: Security Advisory (USN-3677-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3677-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3677-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-hwe, linux-oem' package(s) announced via the USN-3677-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3677-1 fixed vulnerabilities in the Linux kernel for Ubuntu 17.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu 16.04 LTS.

It was discovered that the netfilter subsystem of the Linux kernel did not
properly validate ebtables offsets. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-1068)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly handle corrupted meta data in some situations. An
attacker could use this to specially craft an ext4 file system that caused
a denial of service (system crash) when mounted. (CVE-2018-1092)

It was discovered that a NULL pointer dereference existed in the RDS
(Reliable Datagram Sockets) protocol implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2018-7492)

It was discovered that the 802.11 software simulator implementation in the
Linux kernel contained a memory leak when handling certain error
conditions. A local attacker could possibly use this to cause a denial of
service (memory exhaustion). (CVE-2018-8087)

Eyal Itkin discovered that the USB displaylink video adapter driver in the
Linux kernel did not properly validate mmap offsets sent from userspace. A
local attacker could use this to expose sensitive information (kernel
memory) or possibly execute arbitrary code. (CVE-2018-8781)");

  script_tag(name:"affected", value:"'linux-gcp, linux-hwe, linux-oem' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1019-gcp", ver:"4.13.0-1019.23", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1030-oem", ver:"4.13.0-1030.33", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-45-generic", ver:"4.13.0-45.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-45-generic-lpae", ver:"4.13.0-45.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-45-lowlatency", ver:"4.13.0-45.50~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.13.0.1019.21", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.13.0.45.64", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.13.0.45.64", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.13.0.1019.21", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.13.0.45.64", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.13.0.1030.35", rls:"UBUNTU16.04 LTS"))) {
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
