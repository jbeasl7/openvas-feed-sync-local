# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841135");
  script_cve_id("CVE-2012-2372", "CVE-2012-6547", "CVE-2013-0310");
  script_tag(name:"creation_date", value:"2012-09-07 05:56:49 +0000 (Fri, 07 Sep 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1558-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1558-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1558-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1558-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
protocol implementation. A local, unprivileged user could use this flaw to
cause a denial of service. (CVE-2012-2372)

Mathias Krause discovered an information leak in the Linux kernel's TUN/TAP
device driver. A local user could exploit this flaw to examine part of the
kernel's stack memory. (CVE-2012-6547)

A flaw was found in Linux kernel's validation of CIPSO (Common IP Security
Option) options set from userspace. A local user that can set a socket's
CIPSO options could exploit this flaw to cause a denial of service (crash
the system). (CVE-2013-0310)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-1215-omap4", ver:"3.0.0-1215.27", rls:"UBUNTU11.10"))) {
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
