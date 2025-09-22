# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840951");
  script_cve_id("CVE-2011-4097", "CVE-2012-0038", "CVE-2012-0055", "CVE-2012-0056", "CVE-2012-0207");
  script_tag(name:"creation_date", value:"2012-03-16 05:23:17 +0000 (Fri, 16 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-28 14:33:47 +0000 (Fri, 28 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-1364-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1364-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1364-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1364-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bug was discovered in the Linux kernel's calculation of OOM (Out of
memory) scores, that would result in the wrong process being killed. A user
could use this to kill the process with the highest OOM score, even if that
process belongs to another user or the system. (CVE-2011-4097)

A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code on
the system. (CVE-2012-0038)

Andy Whitcroft discovered a that the Overlayfs filesystem was not doing the
extended permission checks needed by cgroups and Linux Security Modules
(LSMs). A local user could exploit this to by-pass security policy and
access files that should not be accessible. (CVE-2012-0055)

Juri Aedla discovered that the kernel incorrectly handled /proc/<pid>/mem
permissions. A local attacker could exploit this and gain root privileges.
(CVE-2012-0056)

A flaw was found in the linux kernels IPv4 IGMP query processing. A remote
attacker could exploit this to cause a denial of service. (CVE-2012-0207)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 11.10.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-1207-omap4", ver:"3.0.0-1207.16", rls:"UBUNTU11.10"))) {
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
