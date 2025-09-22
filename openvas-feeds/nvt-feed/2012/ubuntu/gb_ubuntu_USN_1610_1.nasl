# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841192");
  script_cve_id("CVE-2012-3520", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6689", "CVE-2013-1827");
  script_tag(name:"creation_date", value:"2012-10-16 04:17:50 +0000 (Tue, 16 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-05 18:44:27 +0000 (Thu, 05 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-1610-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1610-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1610-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1610-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pablo Neira Ayuso discovered a flaw in the credentials of netlink messages.
An unprivileged local attacker could exploit this by getting a netlink
based service, that relies on netlink credentials, to perform privileged
actions. (CVE-2012-3520)

Mathias Krause discovered information leak in the Linux kernel's compat
ioctl interface. A local user could exploit the flaw to examine parts of
kernel stack memory (CVE-2012-6539)

Mathias Krause discovered an information leak in the Linux kernel's
getsockopt for IP_VS_SO_GET_TIMEOUT. A local user could exploit this flaw
to examine parts of kernel stack memory. (CVE-2012-6540)

Mathias Krause discovered an information leak in the Linux kernel's
getsockopt implementation for the Datagram Congestion Control Protocol
(DCCP). A local user could exploit this flaw to examine some of the
kernel's stack memory. (CVE-2012-6541)

Mathias Krause discovered an information leak in the Linux kernel's
getsockname implementation for Logical Link Layer (llc) sockets. A local
user could exploit this flaw to examine some of the kernel's stack memory.
(CVE-2012-6542)

Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
Logical Link Control and Adaptation Protocol (L2CAP) implementation. A
local user could exploit these flaws to examine some of the kernel's stack
memory. (CVE-2012-6544)

Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
RFCOMM protocol implementation. A local user could exploit these flaws to
examine parts of kernel memory. (CVE-2012-6545)

Mathias Krause discovered information leaks in the Linux kernel's
Asynchronous Transfer Mode (ATM) networking stack. A local user could
exploit these flaws to examine some parts of kernel memory. (CVE-2012-6546)

A flaw was discovered in how netlink sockets validate message origins. A
local attacker could exploit this flaw to send netlink message
notifications, with spoofed credentials, to subscribed tasks.
(CVE-2012-6689)

Mathias Krause discover an error in Linux kernel's Datagram Congestion
Control Protocol (DCCP) Congestion Control Identifier (CCID) use. A local
attack could exploit this flaw to cause a denial of service (crash) and
potentially escalate privileges if the user can mmap page 0.
(CVE-2013-1827)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-generic", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-generic-pae", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-highbank", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-omap", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-powerpc-smp", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-powerpc64-smp", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-32-virtual", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS"))) {
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
