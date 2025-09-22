# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841243");
  script_cve_id("CVE-2012-4565", "CVE-2012-6547", "CVE-2012-6638", "CVE-2012-6647", "CVE-2013-0310", "CVE-2013-1827");
  script_tag(name:"creation_date", value:"2012-12-06 04:56:17 +0000 (Thu, 06 Dec 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1653-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1653-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1653-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1653-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rodrigo Freire discovered a flaw in the Linux kernel's TCP illinois
congestion control algorithm. A local attacker could use this to cause a
denial of service. (CVE-2012-4565)

Mathias Krause discovered an information leak in the Linux kernel's TUN/TAP
device driver. A local user could exploit this flaw to examine part of the
kernel's stack memory. (CVE-2012-6547)

Denys Fedoryshchenko discovered a flaw in the Linux kernel's TCP receive
processing for IPv4. A remote attacker could exploit this flaw to cause a
denial of service (kernel resource consumption) via a flood of SYN+FIN TCP
packets. (CVE-2012-6638)

A flaw was discovered in the requeuing of futexes in the Linux kernel. A
local user could exploit this flaw to cause a denial of service (system
crash) or possibly have other unspecified impact. (CVE-2012-6647)

A flaw was found in Linux kernel's validation of CIPSO (Common IP Security
Option) options set from userspace. A local user that can set a socket's
CIPSO options could exploit this flaw to cause a denial of service (crash
the system). (CVE-2013-0310)

Mathias Krause discover an error in Linux kernel's Datagram Congestion
Control Protocol (DCCP) Congestion Control Identifier (CCID) use. A local
attack could exploit this flaw to cause a denial of service (crash) and
potentially escalate privileges if the user can mmap page 0.
(CVE-2013-1827)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-350-ec2", ver:"2.6.32-350.57", rls:"UBUNTU10.04 LTS"))) {
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
