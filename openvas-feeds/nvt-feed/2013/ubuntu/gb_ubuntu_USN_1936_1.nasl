# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841535");
  script_cve_id("CVE-2013-1059", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-4125", "CVE-2013-4127", "CVE-2013-4247");
  script_tag(name:"creation_date", value:"2013-08-27 04:30:42 +0000 (Tue, 27 Aug 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1936-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1936-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-raring' package(s) announced via the USN-1936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chanam Park reported a Null pointer flaw in the Linux kernel's Ceph client.
A remote attacker could exploit this flaw to cause a denial of service
(system crash). (CVE-2013-1059)

An information leak was discovered in the Linux kernel's fanotify
interface. A local user could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2013-2148)

Jonathan Salwan discovered an information leak in the Linux kernel's cdrom
driver. A local user can exploit this leak to obtain sensitive information
from kernel memory if the CD-ROM drive is malfunctioning. (CVE-2013-2164)

Kees Cook discovered a format string vulnerability in the Linux kernel's
disk block layer. A local user with administrator privileges could exploit
this flaw to gain kernel privileges. (CVE-2013-2851)

Kees Cook discovered a format string vulnerability in the Broadcom B43
wireless driver for the Linux kernel. A local user could exploit this flaw
to gain administrative privileges. (CVE-2013-2852)

Hannes Frederic Sowa discovered that the Linux kernel's IPv6 stack does not
correctly handle Router Advertisement (RA) message in some cases. A remote
attacker could exploit this flaw to cause a denial of service (system
crash). (CVE-2013-4125)

A vulnerability was discovered in the Linux kernel's vhost net driver. A
local user could cause a denial of service (system crash) by powering on a
virtual machine. (CVE-2013-4127)

Marcus Moeller and Ken Fallon discovered that the CIFS incorrectly built
certain paths. A local attacker with access to a CIFS partition could
exploit this to crash the system, leading to a denial of service.
(CVE-2013-4247)");

  script_tag(name:"affected", value:"'linux-lts-raring' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.8.0-29-generic", ver:"3.8.0-29.42~precise1", rls:"UBUNTU12.04 LTS"))) {
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
