# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841103");
  script_cve_id("CVE-2011-4131", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-2372", "CVE-2012-2375");
  script_tag(name:"creation_date", value:"2012-08-14 05:10:11 +0000 (Tue, 14 Aug 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1530-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1530-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1530-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1530-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Adamson discovered a flaw in the Linux kernel's NFSv4 implementation.
A remote NFS server (attacker) could exploit this flaw to cause a denial of
service. (CVE-2011-4131)

Steve Grubb reported a flaw with Linux fscaps (file system base
capabilities) when used to increase the permissions of a process. For
application on which fscaps are in use a local attacker can disable address
space randomization to make attacking the process with raised privileges
easier. (CVE-2012-2123)

An error was discovered in the Linux kernel's network TUN/TAP device
implementation. A local user with access to the TUN/TAP interface (which is
not available to unprivileged users until granted by a root user) could
exploit this flaw to crash the system or potential gain administrative
privileges. (CVE-2012-2136)

Stephan Mueller reported a flaw in the Linux kernel's dl2k network driver's
handling of ioctls. An unprivileged local user could leverage this flaw to
cause a denial of service. (CVE-2012-2313)

Timo Warns reported multiple flaws in the Linux kernel's hfsplus
filesystem. An unprivileged local user could exploit these flaws to gain
root system privileges. (CVE-2012-2319)

A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
protocol implementation. A local, unprivileged user could use this flaw to
cause a denial of service. (CVE-2012-2372)

A flaw was discovered in the Linux kernel's NFSv4 (Network file system)
handling of ACLs (access control lists). A remote NFS server (attacker)
could cause a denial of service (OOPS). (CVE-2012-2375)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-1209-omap4", ver:"2.6.38-1209.25", rls:"UBUNTU11.04"))) {
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
