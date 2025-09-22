# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840696");
  script_cve_id("CVE-2010-4243", "CVE-2010-4263", "CVE-2010-4342", "CVE-2010-4529", "CVE-2010-4565", "CVE-2011-0463", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1090", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1573", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1770", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-2534", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-4611", "CVE-2011-4913");
  script_tag(name:"creation_date", value:"2011-07-08 14:31:28 +0000 (Fri, 08 Jul 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-10 13:37:00 +0000 (Mon, 10 Jun 2013)");

  script_name("Ubuntu: Security Advisory (USN-1162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1162-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1162-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-mvl-dove' package(s) announced via the USN-1162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brad Spengler discovered that the kernel did not correctly account for
userspace memory allocations during exec() calls. A local attacker could
exploit this to consume all system memory, leading to a denial of service.
(CVE-2010-4243)

Alexander Duyck discovered that the Intel Gigabit Ethernet driver did not
correctly handle certain configurations. If such a device was configured
without VLANs, a remote attacker could crash the system, leading to a
denial of service. (CVE-2010-4263)

Nelson Elhage discovered that Econet did not correctly handle AUN packets
over UDP. A local attacker could send specially crafted traffic to crash
the system, leading to a denial of service. (CVE-2010-4342)

Dan Rosenberg discovered that IRDA did not correctly check the size of
buffers. On non-x86 systems, a local attacker could exploit this to read
kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

Dan Rosenburg discovered that the CAN subsystem leaked kernel addresses
into the /proc filesystem. A local attacker could use this to increase the
chances of a successful memory corruption exploit. (CVE-2010-4565)

Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
clear memory when writing certain file holes. A local attacker could
exploit this to read uninitialized data from the disk, leading to a loss of
privacy. (CVE-2011-0463)

Jens Kuehnel discovered that the InfiniBand driver contained a race
condition. On systems using InfiniBand, a local attacker could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2011-0695)

Dan Rosenberg discovered that XFS did not correctly initialize memory. A
local attacker could make crafted ioctl calls to leak portions of kernel
stack memory, leading to a loss of privacy. (CVE-2011-0711)

Kees Cook reported that /proc/pid/stat did not correctly filter certain
memory locations. A local attacker could determine the memory layout of
processes in an attempt to increase the chances of a successful memory
corruption exploit. (CVE-2011-0726)

Matthiew Herrb discovered that the drm modeset interface did not correctly
handle a signed comparison. A local attacker could exploit this to crash
the system or possibly gain root privileges. (CVE-2011-1013)

Marek Olsak discovered that the Radeon GPU drivers did not correctly
validate certain registers. On systems with specific hardware, a local
attacker could exploit this to write to arbitrary video memory.
(CVE-2011-1016)

Timo Warns discovered that the LDM disk partition handling code did not
correctly handle certain values. By inserting a specially crafted disk
device, a local attacker could exploit this to gain root privileges.
(CVE-2011-1017)

Vasiliy Kulikov discovered that the CAP_SYS_MODULE capability was not
needed to load kernel modules. A local attacker with the CAP_NET_ADMIN
capability could load existing kernel modules, possibly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-mvl-dove' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-217-dove", ver:"2.6.32-217.34", rls:"UBUNTU10.04 LTS"))) {
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
