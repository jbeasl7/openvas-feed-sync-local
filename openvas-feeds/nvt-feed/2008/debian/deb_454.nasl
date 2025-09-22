# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53152");
  script_cve_id("CVE-2004-0077");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-454)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-454");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-454");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-454");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-image-2.2.22-alpha, kernel-source-2.2.22' package(s) announced via the DSA-454 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical security vulnerability in the memory management code of Linux inside the mremap(2) system call. Due to flushing the TLB (Translation Lookaside Buffer, an address cache) too early it is possible for an attacker to trigger a local root exploit.

The attack vectors for 2.4.x and 2.2.x kernels are exclusive for the respective kernel series, though. We formerly believed that the exploitable vulnerability in 2.4.x does not exist in 2.2.x which is still true. However, it turned out that a second (sort of) vulnerability is indeed exploitable in 2.2.x, but not in 2.4.x, with a different exploit, of course.

For the stable distribution (woody) this problem has been fixed in the following versions and architectures:

package

arch

version

kernel-source-2.2.22

source

2.2.22-1woody1

kernel-image-2.2.22-alpha

alpha

2.2.22-2

For the unstable distribution (sid) this problem will be fixed soon for the architectures that still ship a 2.2.x kernel package.

We recommend that you upgrade your Linux kernel package.

Vulnerability matrix for CAN-2004-0077");

  script_tag(name:"affected", value:"'kernel-image-2.2.22-alpha, kernel-source-2.2.22' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.2.22", ver:"2.2.22-1woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.2.22", ver:"2.2.22-2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.2.22-generic", ver:"2.2.22-2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.2.22-jensen", ver:"2.2.22-2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.2.22-nautilus", ver:"2.2.22-2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.2.22-smp", ver:"2.2.22-2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.2.22", ver:"2.2.22-1woody1", rls:"DEB3.0"))) {
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
