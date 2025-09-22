# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7533.1");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_tag(name:"creation_date", value:"2025-05-27 04:07:40 +0000 (Tue, 27 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:15:54 +0000 (Tue, 15 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7533-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7533-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7533-1");
  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2025-04-15");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-17-crac' package(s) announced via the USN-7533-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alicja Kario discovered that the JSSE component of CRaC JDK 17 incorrectly
handled RSA padding. An attacker could possibly use this issue to obtain
sensitive information. (CVE-2025-21587)

It was discovered that the Compiler component of CRaC JDK 17 incorrectly
handled compiler transformations. An attacker could possibly use this
issue to cause a denial of service or execute arbitrary code.
(CVE-2025-30691)

It was discovered that the 2D component of CRaC JDK 17 did not properly
manage memory under certain circumstances. An attacker could possibly use
this issue to cause a denial of service or execute arbitrary code.
(CVE-2025-30698)

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following link for more information:
[link moved to references]");

  script_tag(name:"affected", value:"'openjdk-17-crac' package(s) on Ubuntu 24.10, Ubuntu 25.04.");

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

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jdk", ver:"17.0.15+6-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jdk-headless", ver:"17.0.15+6-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre", ver:"17.0.15+6-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre-headless", ver:"17.0.15+6-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre-zero", ver:"17.0.15+6-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jdk", ver:"17.0.15+6-0ubuntu1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jdk-headless", ver:"17.0.15+6-0ubuntu1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre", ver:"17.0.15+6-0ubuntu1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre-headless", ver:"17.0.15+6-0ubuntu1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre-zero", ver:"17.0.15+6-0ubuntu1~25.04", rls:"UBUNTU25.04"))) {
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
