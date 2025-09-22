# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840745");
  script_cve_id("CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3874", "CVE-2010-3880", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4256", "CVE-2010-4565", "CVE-2010-4649", "CVE-2010-4655", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1020", "CVE-2011-1044", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1478", "CVE-2011-1493", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1770", "CVE-2011-1833", "CVE-2011-2022", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2918", "CVE-2011-3637", "CVE-2011-4913", "CVE-2011-4914");
  script_tag(name:"creation_date", value:"2011-09-16 15:22:17 +0000 (Fri, 16 Sep 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-10 13:37:00 +0000 (Mon, 10 Jun 2013)");

  script_name("Ubuntu: Security Advisory (USN-1202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");

  script_xref(name:"Advisory-ID", value:"USN-1202-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1202-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that several network ioctls did not clear kernel
memory correctly. A local user could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-3296, CVE-2010-3297)

Brad Spengler discovered that stack memory for new a process was not
correctly calculated. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-3858)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did not
correctly calculate the size of certain buffers. A local attacker could
exploit this to crash the system or possibly execute arbitrary code as the
root user. (CVE-2010-3874)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
properly audit certain bytecodes in netlink messages. A local attacker
could exploit this to cause the kernel to hang, leading to a denial of
service. (CVE-2010-3880)

Dan Rosenberg discovered that IPC structures were not correctly initialized
on 64bit systems. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4073)

Dan Rosenberg discovered that multiple terminal ioctls did not correctly
initialize structure memory. A local attacker could exploit this to read
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2010-4075, CVE-2010-4076, CVE-2010-4077)

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

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)

Dan Rosenberg discovered that certain iovec operations did not calculate
page counts correctly. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered that the SCSI subsystem did not ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-903-omap4", ver:"2.6.35-903.24", rls:"UBUNTU10.10"))) {
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
