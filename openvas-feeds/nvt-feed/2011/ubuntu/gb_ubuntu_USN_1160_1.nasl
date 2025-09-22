# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840691");
  script_cve_id("CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1748", "CVE-2011-2022", "CVE-2011-2534", "CVE-2011-3359", "CVE-2011-4611", "CVE-2011-4913");
  script_tag(name:"creation_date", value:"2011-07-08 14:31:28 +0000 (Fri, 08 Jul 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-10 13:37:00 +0000 (Mon, 10 Jun 2013)");

  script_name("Ubuntu: Security Advisory (USN-1160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");

  script_xref(name:"Advisory-ID", value:"USN-1160-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1160-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that IRDA did not correctly check the size of
buffers. On non-x86 systems, a local attacker could exploit this to read
kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

Dan Rosenburg discovered that the CAN subsystem leaked kernel addresses
into the /proc filesystem. A local attacker could use this to increase the
chances of a successful memory corruption exploit. (CVE-2010-4565)

Kees Cook discovered that the IOWarrior USB device driver did not correctly
check certain size fields. A local attacker with physical access could plug
in a specially crafted USB device to crash the system or potentially gain
root privileges. (CVE-2010-4656)

Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
clear memory when writing certain file holes. A local attacker could
exploit this to read uninitialized data from the disk, leading to a loss of
privacy. (CVE-2011-0463)

Dan Carpenter discovered that the TTPCI DVB driver did not check certain
values during an ioctl. If the dvb-ttpci module was loaded, a local
attacker could exploit this to crash the system, leading to a denial of
service, or possibly gain root privileges. (CVE-2011-0521)

Jens Kuehnel discovered that the InfiniBand driver contained a race
condition. On systems using InfiniBand, a local attacker could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2011-0695)

Dan Rosenberg discovered that XFS did not correctly initialize memory. A
local attacker could make crafted ioctl calls to leak portions of kernel
stack memory, leading to a loss of privacy. (CVE-2011-0711)

Rafael Dominguez Vega discovered that the caiaq Native Instruments USB
driver did not correctly validate string lengths. A local attacker with
physical access could plug in a specially crafted USB device to crash the
system or potentially gain root privileges. (CVE-2011-0712)

Kees Cook reported that /proc/pid/stat did not correctly filter certain
memory locations. A local attacker could determine the memory layout of
processes in an attempt to increase the chances of a successful memory
corruption exploit. (CVE-2011-0726)

Timo Warns discovered that MAC partition parsing routines did not correctly
calculate block counts. A local attacker with physical access could plug in
a specially crafted block device to crash the system or potentially gain
root privileges. (CVE-2011-1010)

Timo Warns discovered that LDM partition parsing routines did not correctly
calculate block counts. A local attacker with physical access could plug in
a specially crafted block device to crash the system, leading to a denial
of service. (CVE-2011-1012)

Matthiew Herrb discovered that the drm modeset interface did not correctly
handle a signed comparison. A local attacker could exploit this to crash
the system or possibly gain root privileges. (CVE-2011-1013)

Marek Olsak discovered ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-omap", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc-smp", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc64-smp", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-versatile", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.54", rls:"UBUNTU10.10"))) {
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
