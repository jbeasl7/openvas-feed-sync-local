# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840081");
  script_cve_id("CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180", "CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04)");

  script_xref(name:"Advisory-ID", value:"USN-479-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-479-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.17, linux-restricted-modules-2.6.20' package(s) announced via the USN-479-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws in the MadWifi driver were discovered that could lead
to a system crash. A physically near-by attacker could generate
specially crafted wireless network traffic and cause a denial of
service. (CVE-2006-7177, CVE-2006-7178, CVE-2006-7179, CVE-2007-2829,
CVE-2007-2830)

A flaw was discovered in the MadWifi driver that would allow unencrypted
network traffic to be sent prior to finishing WPA authentication.
A physically near-by attacker could capture this, leading to a loss of
privacy, denial of service, or network spoofing. (CVE-2006-7180)

A flaw was discovered in the MadWifi driver's ioctl handling. A local
attacker could read kernel memory, or crash the system, leading to a
denial of service. (CVE-2007-2831)");

  script_tag(name:"affected", value:"'linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.17, linux-restricted-modules-2.6.20' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-386", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-686", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-amd64-generic", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-amd64-k8", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-amd64-xeon", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-k7", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-powerpc", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-powerpc-smp", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-sparc64", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.15-28-sparc64-smp", ver:"2.6.15.12-28.2", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-386", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-generic", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-powerpc", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-powerpc-smp", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-powerpc64-smp", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-sparc64", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-11-sparc64-smp", ver:"2.6.17.8-11.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-386", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-generic", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-lowlatency", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-powerpc", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-powerpc-smp", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-powerpc64-smp", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-sparc64", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.20-16-sparc64-smp", ver:"2.6.20.5-16.29", rls:"UBUNTU7.04"))) {
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
