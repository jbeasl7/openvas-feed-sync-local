# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840758");
  script_cve_id("CVE-2011-1576", "CVE-2011-1776", "CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3593");
  script_tag(name:"creation_date", value:"2011-09-30 14:02:57 +0000 (Fri, 30 Sep 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-25 17:39:00 +0000 (Fri, 25 May 2012)");

  script_name("Ubuntu: Security Advisory (USN-1220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");

  script_xref(name:"Advisory-ID", value:"USN-1220-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1220-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
packets. On some systems, a remote attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2011-1576)

Timo Warns discovered that the EFI GUID partition table was not correctly
parsed. A physically local attacker that could insert mountable devices
could exploit this to crash the system or possibly gain root privileges.
(CVE-2011-1776)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit this to
consume CPU resources, leading to a denial of service. (CVE-2011-2213)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote attacker
could send specially crafted traffic to crash the system or gain root
privileges. (CVE-2011-2497)

Mauro Carvalho Chehab discovered that the si4713 radio driver did not
correctly check the length of memory copies. If this hardware was
available, a local attacker could exploit this to crash the system or gain
root privileges. (CVE-2011-2700)

Herbert Xu discovered that certain fields were incorrectly handled when
Generic Receive Offload (CVE-2011-2723)

Time Warns discovered that long symlinks were incorrectly handled on Be
filesystems. A local attacker could exploit this with a malformed Be
filesystem and crash the system, leading to a denial of service.
(CVE-2011-2928)

Dan Kaminsky discovered that the kernel incorrectly handled random sequence
number generation. An attacker could use this flaw to possibly predict
sequence numbers and inject packets. (CVE-2011-3188)

Darren Lavender discovered that the CIFS client incorrectly handled certain
large values. A remote attacker with a malicious server could exploit this
to crash the system or possibly execute arbitrary code as the root user.
(CVE-2011-3191)

Gideon Naim discovered a flaw in the Linux kernel's handling VLAN 0 frames.
An attacker on the local network could exploit this flaw to cause a denial
of service. (CVE-2011-3593)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 10.10.");

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

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-903-omap4", ver:"2.6.35-903.25", rls:"UBUNTU10.10"))) {
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
