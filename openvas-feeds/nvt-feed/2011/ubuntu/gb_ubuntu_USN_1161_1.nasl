# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840698");
  script_cve_id("CVE-2010-3881", "CVE-2011-1017", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1770", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-3363");
  script_tag(name:"creation_date", value:"2011-07-18 13:23:56 +0000 (Mon, 18 Jul 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2011-06-27 14:54:00 +0000 (Mon, 27 Jun 2011)");

  script_name("Ubuntu: Security Advisory (USN-1161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1161-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1161-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vasiliy Kulikov discovered that kvm did not correctly clear memory. A local
attacker could exploit this to read portions of the kernel stack, leading
to a loss of privacy. (CVE-2010-3881)

Timo Warns discovered that the LDM disk partition handling code did not
correctly handle certain values. By inserting a specially crafted disk
device, a local attacker could exploit this to gain root privileges.
(CVE-2011-1017)

Neil Horman discovered that NFSv4 did not correctly handle certain orders
of operation with ACL data. A remote attacker with access to an NFSv4 mount
could exploit this to crash the system, leading to a denial of service.
(CVE-2011-1090)

Timo Warns discovered that OSF partition parsing routines did not correctly
clear memory. A local attacker with physical access could plug in a
specially crafted block device to read kernel memory, leading to a loss of
privacy. (CVE-2011-1163)

Dan Rosenberg discovered that MPT devices did not correctly validate
certain values in ioctl calls. If these drivers were loaded, a local
attacker could exploit this to read arbitrary kernel memory, leading to a
loss of privacy. (CVE-2011-1494, CVE-2011-1495)

Tavis Ormandy discovered that the pidmap function did not correctly handle
large requests. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-1593)

Oliver Hartkopp and Dave Jones discovered that the CAN network driver did
not correctly validate certain socket structures. If this driver was
loaded, a local attacker could crash the system, leading to a denial of
service. (CVE-2011-1598, CVE-2011-1748)

Vasiliy Kulikov discovered that the AGP driver did not check certain ioctl
values. A local attacker with access to the video subsystem could exploit
this to crash the system, leading to a denial of service, or possibly gain
root privileges. (CVE-2011-1745, CVE-2011-2022)

Vasiliy Kulikov discovered that the AGP driver did not check the size of
certain memory allocations. A local attacker with access to the video
subsystem could exploit this to run the system out of memory, leading to a
denial of service. (CVE-2011-1746)

Dan Rosenberg reported an error in the old ABI compatibility layer of ARM
kernels. A local attacker could exploit this flaw to cause a denial of
service or gain root privileges. (CVE-2011-1759)

Dan Rosenberg discovered that the DCCP stack did not correctly handle
certain packet structures. A remote attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2011-1770)

Timo Warns discovered that the EFI GUID partition table was not correctly
parsed. A physically local attacker that could insert mountable devices
could exploit this to crash the system or possibly gain root privileges.
(CVE-2011-1776)

Yogesh Sharma discovered that CIFS did not correctly handle UNCs that had
no prefixpaths. A local attacker with access to a CIFS partition ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-317-ec2", ver:"2.6.32-317.36", rls:"UBUNTU10.04 LTS"))) {
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
