# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841302");
  script_cve_id("CVE-2012-4461", "CVE-2012-4530", "CVE-2012-5532");
  script_tag(name:"creation_date", value:"2013-02-04 04:27:34 +0000 (Mon, 04 Feb 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1699-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");

  script_xref(name:"Advisory-ID", value:"USN-1699-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1699-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1101666");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1699-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1699-1 fixed vulnerabilities in the Linux kernel. Due to an unrelated
regression inotify/fanotify stopped working after upgrading. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Jon Howell reported a flaw in the Linux kernel's KVM (Kernel-based virtual
 machine) subsystem's handling of the XSAVE CPU feature. On hosts without the
 XSAVE CPU feature, using qemu userspace, an unprivileged local attacker could
 exploit this flaw to crash the system. (CVE-2012-4461)

 A flaw was discovered in the Linux kernel's handling of script execution
 when module loading is enabled. A local attacker could exploit this flaw to
 cause a leak of kernel stack contents. (CVE-2012-4530)

 Florian Weimer discovered that hypervkvpd, which is distributed in the
 Linux kernel, was not correctly validating source addresses of netlink
 packets. An untrusted local user can cause a denial of service by causing
 hypervkvpd to exit. (CVE-2012-5532)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.10.");

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

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-23-generic", ver:"3.5.0-23.35", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-23-highbank", ver:"3.5.0-23.35", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-23-omap", ver:"3.5.0-23.35", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-23-powerpc-smp", ver:"3.5.0-23.35", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-23-powerpc64-smp", ver:"3.5.0-23.35", rls:"UBUNTU12.10"))) {
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
