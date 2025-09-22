# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840632");
  script_cve_id("CVE-2010-4075", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4242", "CVE-2010-4258", "CVE-2010-4346", "CVE-2010-4668");
  script_tag(name:"creation_date", value:"2011-04-11 13:05:25 +0000 (Mon, 11 Apr 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1105-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1105-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that multiple terminal ioctls did not correctly
initialize structure memory. A local attacker could exploit this to read
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2010-4075)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered that certain iovec operations did not calculate
page counts correctly. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
iov segments. A local attacker with access to a SCSI device could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2010-4163, CVE-2010-4668)

Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing. If
a system was using X.25, a remote attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4164)

Alan Cox discovered that the HCI UART driver did not correctly check if a
write operation was available. If the mmap_min-addr sysctl was changed from
the Ubuntu default to a value of 0, a local attacker could exploit this
flaw to gain root privileges. (CVE-2010-4242)

Nelson Elhage discovered that the kernel did not correctly handle process
cleanup after triggering a recoverable kernel bug. If a local attacker were
able to trigger certain kinds of kernel bugs, they could create a specially
crafted process to gain root privileges. (CVE-2010-4258)

Tavis Ormandy discovered that the install_special_mapping function could
bypass the mmap_min_addr restriction. A local attacker could exploit this
to mmap 4096 bytes below the mmap_min_addr area, possibly improving the
chances of performing NULL pointer dereference attacks. (CVE-2010-4346)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 8.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-386", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-generic", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-hppa32", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-hppa64", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-itanium", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-lpia", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-lpiacompat", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-mckinley", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-openvz", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc-smp", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc64-smp", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-rt", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-server", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-sparc64", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-sparc64-smp", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-virtual", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-xen", ver:"2.6.24-29.88", rls:"UBUNTU8.04 LTS"))) {
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
