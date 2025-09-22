# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842440");
  script_cve_id("CVE-2015-0275", "CVE-2015-3636", "CVE-2015-4036");
  script_tag(name:"creation_date", value:"2015-09-18 08:42:52 +0000 (Fri, 18 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.04");

  script_xref(name:"Advisory-ID", value:"USN-2638-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2638-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xiong Zhou discovered a bug in the way the EXT4 filesystem handles
fallocate zero range functionality when the page size is greater than the
block size. A local attacker could exploit this flaw to cause a denial of
service (system crash). (CVE-2015-0275)

Wen Xu discovered a use-after-free flaw in the Linux kernel's ipv4 ping
support. A local user could exploit this flaw to cause a denial of service
(system crash) or gain administrative privileges on the system.
(CVE-2015-3636)

A memory corruption flaw was discovered in the Linux kernel's scsi
subsystem. A local attacker could potentially exploit this flaw to cause a
denial of service (system crash). (CVE-2015-4036)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.04.");

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

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-generic", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-generic-lpae", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-lowlatency", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-powerpc-e500mc", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-powerpc-smp", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-powerpc64-emb", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-20-powerpc64-smp", ver:"3.19.0-20.20", rls:"UBUNTU15.04"))) {
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
