# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841545");
  script_cve_id("CVE-2013-1059", "CVE-2013-1060", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2851", "CVE-2013-4162", "CVE-2013-4163");
  script_tag(name:"creation_date", value:"2013-09-12 06:10:47 +0000 (Thu, 12 Sep 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1941-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1941-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1941-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1941-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chanam Park reported a Null pointer flaw in the Linux kernel's Ceph client.
A remote attacker could exploit this flaw to cause a denial of service
(system crash). (CVE-2013-1059)

Vasily Kulikov discovered a flaw in the Linux Kernel's perf tool that
allows for privilege escalation. A local user could exploit this flaw to
run commands as root when using the perf tool. (CVE-2013-1060)

Jonathan Salwan discovered an information leak in the Linux kernel's cdrom
driver. A local user can exploit this leak to obtain sensitive information
from kernel memory if the CD-ROM drive is malfunctioning. (CVE-2013-2164)

A flaw was discovered in the Linux kernel when an IPv6 socket is used to
connect to an IPv4 destination. An unprivileged local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2013-2232)

An information leak was discovered in the IPSec key_socket implementation
in the Linux kernel. An local user could exploit this flaw to examine
potentially sensitive information in kernel memory. (CVE-2013-2234)

Kees Cook discovered a format string vulnerability in the Linux kernel's
disk block layer. A local user with administrator privileges could exploit
this flaw to gain kernel privileges. (CVE-2013-2851)

Hannes Frederic Sowa discovered a flaw in setsockopt UDP_CORK option in the
Linux kernel's IPv6 stack. A local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2013-4162)

Hannes Frederic Sowa discovered a flaw in the IPv6 subsystem of the Linux
kernel when the IPV6_MTU setsockopt option has been specified in
combination with the UDP_CORK option. A local user could exploit this flaw
to cause a denial of service (system crash). (CVE-2013-4163)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-generic", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-generic-pae", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-highbank", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-omap", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-powerpc-smp", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-powerpc64-smp", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-53-virtual", ver:"3.2.0-53.81", rls:"UBUNTU12.04 LTS"))) {
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
