# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840916");
  script_cve_id("CVE-2011-1759", "CVE-2011-1927", "CVE-2011-2182", "CVE-2011-2498", "CVE-2011-2518", "CVE-2011-3619");
  script_tag(name:"creation_date", value:"2012-03-07 05:49:28 +0000 (Wed, 07 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 15:53:46 +0000 (Tue, 25 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-1383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1383-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1383-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aristide Fattori and Roberto Paleari reported a flaw in the Linux kernel's
handling of IPv4 icmp packets. A remote user could exploit this to cause a
denial of service. (CVE-2011-1927)

Dan Rosenberg reported an error in the old ABI compatibility layer of ARM
kernels. A local attacker could exploit this flaw to cause a denial of
service or gain root privileges. (CVE-2011-1759)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of service or
escalate privileges. (CVE-2011-2182)

The linux kernel did not properly account for PTE pages when deciding which
task to kill in out of memory conditions. A local, unprivileged could
exploit this flaw to cause a denial of service. (CVE-2011-2498)

A flaw was discovered in the TOMOYO LSM's handling of mount system calls.
An unprivileged user could oops the system causing a denial of service.
(CVE-2011-2518)

A flaw was discovered in the Linux kernel's AppArmor security interface
when invalid information was written to it. An unprivileged local user
could use this to cause a denial of service on the system. (CVE-2011-3619)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-1209-omap4", ver:"2.6.38-1209.22", rls:"UBUNTU11.04"))) {
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
