# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840693");
  script_cve_id("CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4164", "CVE-2010-4248", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-1017", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-2022");
  script_tag(name:"creation_date", value:"2011-07-08 14:31:28 +0000 (Fri, 08 Jul 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2011-07-19 12:38:00 +0000 (Tue, 19 Jul 2011)");

  script_name("Ubuntu: Security Advisory (USN-1164-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1164-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1164-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fsl-imx51' package(s) announced via the USN-1164-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash the
system or possibly execute arbitrary code as the root user. (CVE-2010-3865)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did not
correctly calculate the size of certain buffers. A local attacker could
exploit this to crash the system or possibly execute arbitrary code as the
root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
not correctly clear kernel memory. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
not properly initialize certain structures. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3877)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
properly audit certain bytecodes in netlink messages. A local attacker
could exploit this to cause the kernel to hang, leading to a denial of
service. (CVE-2010-3880)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface driver
did not correctly clear kernel memory. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy. (CVE-2010-4080,
CVE-2010-4081)

Dan Rosenberg discovered that the VIA video driver did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4082)

Dan Rosenberg discovered that the semctl syscall did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4083)

James Bottomley discovered that the ICP vortex storage array controller
driver did not validate certain sizes. A local attacker on a 64bit system
could exploit this to crash the kernel, leading to a denial of service.
(CVE-2010-4157)

Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing. If
a system was using X.25, a remote attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4164)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2010-4248)

Nelson Elhage discovered that the kernel did not correctly handle ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-fsl-imx51' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-609-imx51", ver:"2.6.31-609.26", rls:"UBUNTU10.04 LTS"))) {
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
