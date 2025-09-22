# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840740");
  script_cve_id("CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1770", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-3637", "CVE-2011-4914");
  script_tag(name:"creation_date", value:"2011-09-16 15:22:17 +0000 (Fri, 16 Sep 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2011-06-27 14:54:00 +0000 (Mon, 27 Jun 2011)");

  script_name("Ubuntu: Security Advisory (USN-1201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.10");

  script_xref(name:"Advisory-ID", value:"USN-1201-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1201-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1201-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could hold open
files to examine details about programs running with higher privileges,
potentially increasing the chances of exploiting additional
vulnerabilities. (CVE-2011-1020)

Dan Rosenberg discovered that the X.25 Rose network stack did not correctly
handle certain fields. If a system was running with Rose enabled, a remote
attacker could send specially crafted traffic to gain root privileges.
(CVE-2011-1493)

Dan Rosenberg discovered that the DCCP stack did not correctly handle
certain packet structures. A remote attacker could exploit this to crash
the system, leading to a denial of service. (CVE-2011-1770)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484)

It was discovered that Bluetooth l2cap and rfcomm did not correctly
initialize structures. A local attacker could exploit this to read portions
of the kernel stack, leading to a loss of privacy. (CVE-2011-2492)

A flaw was found in the Linux kernel's /proc/*/*map* interface. A local,
unprivileged user could exploit this flaw to cause a denial of service.
(CVE-2011-3637)

Ben Hutchings discovered several flaws in the Linux Rose (X.25 PLP) layer.
A local user or a remote user on an X.25 network could exploit these flaws
to execute arbitrary code as root. (CVE-2011-4914)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.10.");

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

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-omap", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc-smp", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-powerpc64-smp", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-versatile", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.59", rls:"UBUNTU10.10"))) {
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
