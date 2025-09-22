# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841391");
  script_cve_id("CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1792");
  script_tag(name:"creation_date", value:"2013-04-15 04:47:29 +0000 (Mon, 15 Apr 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1798-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1798-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1798-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1798-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Krause discovered several errors in the Linux kernel's xfrm_user
implementation. A local attacker could exploit these flaws to examine parts
of kernel memory. (CVE-2012-6537)

Mathias Krause discovered information leak in the Linux kernel's compat
ioctl interface. A local user could exploit the flaw to examine parts of
kernel stack memory (CVE-2012-6539)

Mathias Krause discovered an information leak in the Linux kernel's
getsockopt for IP_VS_SO_GET_TIMEOUT. A local user could exploit this flaw
to examine parts of kernel stack memory. (CVE-2012-6540)

Emese Revfy discovered that in the Linux kernel signal handlers could leak
address information across an exec, making it possible to by pass ASLR
(Address Space Layout Randomization). A local user could use this flaw to
by pass ASLR to reliably deliver an exploit payload that would otherwise be
stopped (by ASLR). (CVE-2013-0914)

A memory use after free error was discover in the Linux kernel's tmpfs
filesystem. A local user could exploit this flaw to gain privileges or
cause a denial of service (system crash). (CVE-2013-1767)

Mateusz Guzik discovered a race in the Linux kernel's keyring. A local user
could exploit this flaw to cause a denial of service (system crash).
(CVE-2013-1792)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-351-ec2", ver:"2.6.32-351.63", rls:"UBUNTU10.04 LTS"))) {
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
