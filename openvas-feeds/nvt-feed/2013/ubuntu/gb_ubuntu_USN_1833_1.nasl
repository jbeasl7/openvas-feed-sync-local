# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841435");
  script_cve_id("CVE-2013-1929", "CVE-2013-1979", "CVE-2013-2141", "CVE-2013-3301");
  script_tag(name:"creation_date", value:"2013-05-27 06:24:47 +0000 (Mon, 27 May 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1833-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1833-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1833-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Lutomirski discover an error in the Linux kernel's credential handling
on unix sockets. A local user could exploit this flaw to gain
administrative privileges. (CVE-2013-1979)

A buffer overflow vulnerability was discovered in the Broadcom tg3 ethernet
driver for the Linux kernel. A local user could exploit this flaw to cause
a denial of service (crash the system) or potentially escalate privileges
on the system. (CVE-2013-1929)

An information leak was discovered in the Linux kernel's tkill and tgkill
system calls when used from compat processes. A local user could exploit
this flaw to examine potentially sensitive kernel memory. (CVE-2013-2141)

A flaw was discovered in the Linux kernel's ftrace subsystem interface. A
local user could exploit this flaw to cause a denial of service (system
crash). (CVE-2013-3301)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-generic", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-generic-pae", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-highbank", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-omap", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-powerpc-smp", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-powerpc64-smp", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-44-virtual", ver:"3.2.0-44.69", rls:"UBUNTU12.04 LTS"))) {
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
