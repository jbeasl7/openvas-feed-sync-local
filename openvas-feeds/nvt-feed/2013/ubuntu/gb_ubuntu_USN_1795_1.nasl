# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841393");
  script_cve_id("CVE-2013-0228", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1792", "CVE-2013-2546", "CVE-2013-2547", "CVE-2013-2548");
  script_tag(name:"creation_date", value:"2013-04-15 04:48:43 +0000 (Mon, 15 Apr 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1795-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1795-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1795-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-quantal' package(s) announced via the USN-1795-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
guest OS user could exploit this flaw to cause a denial of service (crash
the system) or gain guest OS privilege. (CVE-2013-0228)

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
(CVE-2013-1792)

Mathias Krause discovered a memory leak in the Linux kernel's crypto report
API. A local user with CAP_NET_ADMIN could exploit this leak to examine
some of the kernel's stack memory. (CVE-2013-2546)

Mathias Krause discovered a memory leak in the Linux kernel's crypto report
API. A local user with CAP_NET_ADMIN could exploit this leak to examine
some of the kernel's heap memory. (CVE-2013-2547)

Mathias Krause discovered information leaks in the Linux kernel's crypto
algorithm report API. A local user could exploit these flaws to leak kernel
stack and heap memory contents. (CVE-2013-2548)");

  script_tag(name:"affected", value:"'linux-lts-quantal' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-27-generic", ver:"3.5.0-27.46~precise1", rls:"UBUNTU12.04 LTS"))) {
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
