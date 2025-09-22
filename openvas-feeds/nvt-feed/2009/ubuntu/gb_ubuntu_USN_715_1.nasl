# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63309");
  script_cve_id("CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300", "CVE-2008-5395", "CVE-2008-5700", "CVE-2008-5702");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-715-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.10");

  script_xref(name:"Advisory-ID", value:"USN-715-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-715-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-715-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hugo Dias discovered that the ATM subsystem did not correctly manage
socket counts. A local attacker could exploit this to cause a system hang,
leading to a denial of service. (CVE-2008-5079)

It was discovered that the inotify subsystem contained watch removal
race conditions. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2008-5182)

Dann Frazier discovered that in certain situations sendmsg did not
correctly release allocated memory. A local attacker could exploit
this to force the system to run out of free memory, leading to a denial
of service. (CVE-2008-5300)

Helge Deller discovered that PA-RISC stack unwinding was not handled
correctly. A local attacker could exploit this to crash the system,
leading do a denial of service. This did not affect official Ubuntu
kernels, but was fixed in the source for anyone performing HPPA kernel
builds. (CVE-2008-5395)

It was discovered that the ATA subsystem did not correctly set timeouts. A
local attacker could exploit this to cause a system hang, leading to a
denial of service. (CVE-2008-5700)

It was discovered that the ib700 watchdog timer did not correctly check
buffer sizes. A local attacker could send a specially crafted ioctl
to the device to cause a system crash, leading to a denial of service.
(CVE-2008-5702)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 8.10.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-11-generic", ver:"2.6.27-11.27", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-11-server", ver:"2.6.27-11.27", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-11-virtual", ver:"2.6.27-11.27", rls:"UBUNTU8.10"))) {
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
