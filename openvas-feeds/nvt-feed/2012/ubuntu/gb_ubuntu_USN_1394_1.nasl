# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840927");
  script_cve_id("CVE-2010-4250", "CVE-2010-4650", "CVE-2011-0006", "CVE-2011-0716", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1759", "CVE-2011-1927", "CVE-2011-2182", "CVE-2011-3619", "CVE-2011-4621", "CVE-2012-0038", "CVE-2012-0044");
  script_tag(name:"creation_date", value:"2012-03-09 04:56:06 +0000 (Fri, 09 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-17 15:59:00 +0000 (Thu, 17 May 2012)");

  script_name("Ubuntu: Security Advisory (USN-1394-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");

  script_xref(name:"Advisory-ID", value:"USN-1394-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1394-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1394-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aristide Fattori and Roberto Paleari reported a flaw in the Linux kernel's
handling of IPv4 icmp packets. A remote user could exploit this to cause a
denial of service. (CVE-2011-1927)

Vegard Nossum discovered a leak in the kernel's inotify_init() system call.
A local, unprivileged user could exploit this to cause a denial of service.
(CVE-2010-4250)

An error was discovered in the kernel's handling of CUSE (Character device
in Userspace). A local attacker might exploit this flaw to escalate
privilege, if access to /dev/cuse has been modified to allow non-root
users. (CVE-2010-4650)

A flaw was found in the kernel's Integrity Measurement Architecture (IMA).
Changes made by an attacker might not be discovered by IMA, if SELinux was
disabled, and a new IMA rule was loaded. (CVE-2011-0006)

A flaw was found in the Linux Ethernet bridge's handling of IGMP (Internet
Group Management Protocol) packets. An unprivileged local user could
exploit this flaw to crash the system. (CVE-2011-0716)

Dan Rosenberg reported errors in the OSS (Open Sound System) MIDI
interface. A local attacker on non-x86 systems might be able to cause a
denial of service. (CVE-2011-1476)

Dan Rosenberg reported errors in the kernel's OSS (Open Sound System)
driver for Yamaha FM synthesizer chips. A local user can exploit this to
cause memory corruption, causing a denial of service or privilege
escalation. (CVE-2011-1477)

Dan Rosenberg reported an error in the old ABI compatibility layer of ARM
kernels. A local attacker could exploit this flaw to cause a denial of
service or gain root privileges. (CVE-2011-1759)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of service or
escalate privileges. (CVE-2011-2182)

A flaw was discovered in the Linux kernel's AppArmor security interface
when invalid information was written to it. An unprivileged local user
could use this to cause a denial of service on the system. (CVE-2011-3619)

It was discovered that some import kernel threads can be blocked by a user
level process. An unprivileged local user could exploit this flaw to cause
a denial of service. (CVE-2011-4621)

A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code on
the system. (CVE-2012-0038)

Chen Haogang discovered an integer overflow that could result in memory
corruption. A local unprivileged user could use this to crash the system.
(CVE-2012-0044)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-903-omap4", ver:"2.6.35-903.32", rls:"UBUNTU10.10"))) {
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
