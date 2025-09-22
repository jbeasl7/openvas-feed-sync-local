# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841870");
  script_cve_id("CVE-2014-0077", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2568", "CVE-2014-2580", "CVE-2014-2851", "CVE-2014-3122", "CVE-2014-3153", "CVE-2014-7283");
  script_tag(name:"creation_date", value:"2014-07-01 16:12:04 +0000 (Tue, 01 Jul 2014)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 12:17:50 +0000 (Tue, 02 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-2260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2260-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2260-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Linux kernel's pseudo tty (pty) device. An
unprivileged user could exploit this flaw to cause a denial of service
(system crash) or potentially gain administrator privileges.
(CVE-2014-0196)

Pinkie Pie discovered a flaw in the Linux kernel's futex subsystem. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or gain administrative privileges. (CVE-2014-3153)

Matthew Daley reported an information leak in the floppy disk driver of the
Linux kernel. An unprivileged local user could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges if the floppy disk
module is loaded. (CVE-2014-1737)

A flaw was discovered in the handling of network packets when mergeable
buffers are disabled for virtual machines in the Linux kernel. Guest OS
users may exploit this flaw to cause a denial of service (host OS crash) or
possibly gain privilege on the host OS. (CVE-2014-0077)

An information leak was discovered in the netfilter subsystem of the Linux
kernel. An attacker could exploit this flaw to obtain sensitive information
from kernel memory. (CVE-2014-2568)

Torok Edwin discovered a flaw with Xen netback driver when used with
Linux configurations that do not allow sleeping in softirq context. A guest
administrator could exploit this flaw to cause a denial of service (system
crash) on the host. (CVE-2014-2580)

A flaw was discovered in the Linux kernel's ping sockets. An unprivileged
local user could exploit this flaw to cause a denial of service (system
crash) or possibly gain privileges via a crafted application.
(CVE-2014-2851)

Sasha Levin reported a bug in the Linux kernel's virtual memory management
subsystem. An unprivileged local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-3122)

Hannes Frederic Sowa reported a hash collision ordering problem in the xfs
filesystem in the Linux kernel. A local user could exploit this flaw to
cause filesystem corruption and a denial of service (oops or panic).
(CVE-2014-7283)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-30-generic", ver:"3.13.0-30.54~precise2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-30-generic-lpae", ver:"3.13.0-30.54~precise2", rls:"UBUNTU12.04 LTS"))) {
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
