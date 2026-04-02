# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8105.2");
  script_tag(name:"creation_date", value:"2026-03-20 04:34:56 +0000 (Fri, 20 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8105-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8105-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8105-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2144889");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp3' package(s) announced via the USN-8105-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8105-1 fixed vulnerabilities in FreeRDP. The update introduced a
regression which could cause FreeRDP to crash. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that FreeRDP incorrectly handled certain RDP packets. A
 remote attacker could use this issue to cause FreeRDP to crash, resulting
 in a denial of service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'freerdp3' package(s) on Ubuntu 24.04, Ubuntu 25.10.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp3-3", ver:"3.5.1+dfsg1-0ubuntu1.5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp3-3", ver:"3.16.0+dfsg-2ubuntu0.4", rls:"UBUNTU25.10"))) {
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
