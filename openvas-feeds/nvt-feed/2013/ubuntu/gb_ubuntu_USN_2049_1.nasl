# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841655");
  script_cve_id("CVE-2013-4270", "CVE-2013-4299", "CVE-2013-4343", "CVE-2013-4350", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-6431", "CVE-2013-7027", "CVE-2014-1444", "CVE-2014-1445");
  script_tag(name:"creation_date", value:"2013-12-17 06:38:51 +0000 (Tue, 17 Dec 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  script_xref(name:"Advisory-ID", value:"USN-2049-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2049-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Miroslav Vadkerti discovered a flaw in how the permissions for network
sysctls are handled in the Linux kernel. An unprivileged local user could
exploit this flaw to have privileged access to files in /proc/sys/net/.
(CVE-2013-4270)

A flaw was discovered in the Linux kernel's dm snapshot facility. A remote
authenticated user could exploit this flaw to obtain sensitive information
or modify/corrupt data. (CVE-2013-4299)

Wannes Rombouts reported a vulnerability in the networking tuntap interface
of the Linux kernel. A local user with the CAP_NET_ADMIN capability could
leverage this flaw to gain full admin privileges. (CVE-2013-4343)

Alan Chester reported a flaw in the IPv6 Stream Control Transmission
Protocol (SCTP) of the Linux kernel. A remote attacker could exploit this
flaw to obtain sensitive information by sniffing network traffic.
(CVE-2013-4350)

Dmitry Vyukov reported a flaw in the Linux kernel's handling of IPv6 UDP
Fragmentation Offload (UFO) processing. A remote attacker could leverage
this flaw to cause a denial of service (system crash). (CVE-2013-4387)

Hannes Frederic Sowa discovered a flaw in the Linux kernel's UDP
Fragmentation Offload (UFO). An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2013-4470)

A flaw was discovered in the Linux kernel's fib6 error-code encoding for
IPv6. A local user with the CAT_NET_ADMIN capability could exploit this
flaw to cause a denial of service (system crash). (CVE-2013-6431)

Evan Huus reported a buffer overflow in the Linux kernel's radiotap header
parsing. A remote attacker could cause a denial of service (buffer over-
read) via a specially crafted header. (CVE-2013-7027)

An information leak was discovered in the Linux kernel's SIOCWANDEV ioctl
call. A local user with the CAP_NET_ADMIN capability could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-1444)

An information leak was discovered in the wanxl ioctl function the Linux
kernel. A local user could exploit this flaw to obtain potentially
sensitive information from kernel memory. (CVE-2014-1445)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 13.10.");

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

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.11.0-14-generic", ver:"3.11.0-14.21", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.11.0-14-generic-lpae", ver:"3.11.0-14.21", rls:"UBUNTU13.10"))) {
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
