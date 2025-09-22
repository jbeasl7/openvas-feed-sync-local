# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703348");
  script_cve_id("CVE-2015-3214", "CVE-2015-5154", "CVE-2015-5165", "CVE-2015-5225", "CVE-2015-5745");
  script_tag(name:"creation_date", value:"2015-09-01 22:00:00 +0000 (Tue, 01 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 21:03:28 +0000 (Tue, 28 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3348-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3348-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3348");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-3348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in qemu, a fast processor emulator.

CVE-2015-3214

Matt Tait of Google's Project Zero security team discovered a flaw in the QEMU i8254 PIT emulation. A privileged guest user in a guest with QEMU PIT emulation enabled could potentially use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2015-5154

Kevin Wolf of Red Hat discovered a heap buffer overflow flaw in the IDE subsystem in QEMU while processing certain ATAPI commands. A privileged guest user in a guest with the CDROM drive enabled could potentially use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2015-5165

Donghai Zhu discovered that the QEMU model of the RTL8139 network card did not sufficiently validate inputs in the C+ mode offload emulation, allowing a malicious guest to read uninitialized memory from the QEMU process's heap.

CVE-2015-5225

Mr Qinghao Tang from QIHU 360 Inc. and Mr Zuozhi from Alibaba Inc discovered a buffer overflow flaw in the VNC display driver leading to heap memory corruption. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash), or potentially to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2015-5745

A buffer overflow vulnerability was discovered in the way QEMU handles the virtio-serial device. A malicious guest could use this flaw to mount a denial of service (QEMU process crash).

For the oldstable distribution (wheezy), these problems have been fixed in version 1.1.2+dfsg-6a+deb7u9. The oldstable distribution is only affected by CVE-2015-5165 and CVE-2015-5745.

For the stable distribution (jessie), these problems have been fixed in version 1:2.1+dfsg-12+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 1:2.4+dfsg-1a.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u2", rls:"DEB8"))) {
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
