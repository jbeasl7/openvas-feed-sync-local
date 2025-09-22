# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842710");
  script_cve_id("CVE-2015-7833", "CVE-2015-8812", "CVE-2016-2085", "CVE-2016-2383", "CVE-2016-2550", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-04-07 03:01:10 +0000 (Thu, 07 Apr 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-2947-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.10");

  script_xref(name:"Advisory-ID", value:"USN-2947-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2947-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2947-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ralf Spenneberg discovered that the usbvision driver in the Linux kernel
did not properly validate the interfaces and endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7833)

Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
kernel's CXGB3 driver. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

Xiaofei Rex Guo discovered a timing side channel vulnerability in the Linux
Extended Verification Module (EVM). An attacker could use this to affect
system integrity. (CVE-2016-2085)

It was discovered that the extended Berkeley Packet Filter (eBPF)
implementation in the Linux kernel did not correctly compute branch offsets
for backward jumps after ctx expansion. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2016-2383)

David Herrmann discovered that the Linux kernel incorrectly accounted file
descriptors to the original opener for in-flight file descriptors sent over
a unix domain socket. A local attacker could use this to cause a denial of
service (resource exhaustion). (CVE-2016-2550)

It was discovered that the Linux kernel did not enforce limits on the
amount of data allocated to buffer pipes. A local attacker could use this
to cause a denial of service (resource exhaustion). (CVE-2016-2847)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.10.");

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

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-generic", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-generic-lpae", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-lowlatency", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc-e500mc", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc-smp", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc64-emb", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc64-smp", ver:"4.2.0-35.40", rls:"UBUNTU15.10"))) {
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
