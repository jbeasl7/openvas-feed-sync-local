# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843233");
  script_cve_id("CVE-2017-1000363", "CVE-2017-5577", "CVE-2017-7294", "CVE-2017-7374", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2017-06-30 03:14:44 +0000 (Fri, 30 Jun 2017)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-31 17:33:40 +0000 (Wed, 31 May 2017)");

  script_name("Ubuntu: Security Advisory (USN-3342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.10");

  script_xref(name:"Advisory-ID", value:"USN-3342-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3342-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1699772");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3326-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-raspi2' package(s) announced via the USN-3342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN 3326-1 fixed a vulnerability in the Linux kernel. However, that
fix introduced regressions for some Java applications. This update
addresses the issue. We apologize for the inconvenience.

It was discovered that a use-after-free flaw existed in the filesystem
encryption subsystem in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash). (CVE-2017-7374)

Roee Hay discovered that the parallel port printer driver in the Linux
kernel did not properly bounds check passed arguments. A local attacker
with write access to the kernel command line arguments could use this to
execute arbitrary code. (CVE-2017-1000363)

Ingo Molnar discovered that the VideoCore DRM driver in the Linux kernel
did not return an error after detecting certain overflows. A local attacker
could exploit this issue to cause a denial of service (OOPS).
(CVE-2017-5577)

Li Qiang discovered that an integer overflow vulnerability existed in the
Direct Rendering Manager (DRM) driver for VMWare devices in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-7294)

It was discovered that a double-free vulnerability existed in the IPv4
stack of the Linux kernel. An attacker could use this to cause a denial of
service (system crash). (CVE-2017-8890)

Andrey Konovalov discovered an IPv6 out-of-bounds read error in the Linux
kernel's IPv6 stack. A local attacker could cause a denial of service or
potentially other unspecified problems. (CVE-2017-9074)

Andrey Konovalov discovered a flaw in the handling of inheritance in the
Linux kernel's IPv6 stack. A local user could exploit this issue to cause a
denial of service or possibly other unspecified problems. (CVE-2017-9075)

It was discovered that dccp v6 in the Linux kernel mishandled inheritance.
A local attacker could exploit this issue to cause a denial of service or
potentially other unspecified problems. (CVE-2017-9076)

It was discovered that the transmission control protocol (tcp) v6 in the
Linux kernel mishandled inheritance. A local attacker could exploit this
issue to cause a denial of service or potentially other unspecified
problems. (CVE-2017-9077)

It was discovered that the IPv6 stack in the Linux kernel was performing
its over write consistency check after the data was actually overwritten. A
local attacker could exploit this flaw to cause a denial of service (system
crash). (CVE-2017-9242)");

  script_tag(name:"affected", value:"'linux, linux-raspi2' package(s) on Ubuntu 16.10.");

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

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-1042-raspi2", ver:"4.8.0-1042.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-58-generic", ver:"4.8.0-58.63", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-58-generic-lpae", ver:"4.8.0-58.63", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-58-lowlatency", ver:"4.8.0-58.63", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-58-powerpc-e500mc", ver:"4.8.0-58.63", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-58-powerpc-smp", ver:"4.8.0-58.63", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-58-powerpc64-emb", ver:"4.8.0-58.63", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.8.0.1042.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.8.0.58.71", rls:"UBUNTU16.10"))) {
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
