# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7525.2");
  script_cve_id("CVE-2025-24813");
  script_tag(name:"creation_date", value:"2025-05-28 04:06:02 +0000 (Wed, 28 May 2025)");
  script_version("2025-05-28T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-05-28 05:40:15 +0000 (Wed, 28 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-18 14:15:43 +0000 (Tue, 18 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7525-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7525-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7525-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat9' package(s) announced via the USN-7525-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7525-1 fixed CVE-2025-24813 for tomcat9 in Ubuntu 22.04 LTS,
Ubuntu 20.04 LTS, and Ubuntu 18.04 LTS. This update fixes it for
tomcat9 in Ubuntu 24.04 LTS, Ubuntu 24.10, and Ubuntu 25.10.
These versions include only the tomcat library (libtomcat9-java)
and not the full tomcat server stack.

Original advisory details:

It was discovered that Apache Tomcat incorrectly implemented partial
PUT functionality by replacing path separators with dots in temporary
files. A remote attacker could possibly use this issue to access
sensitive files, inject malicious content, or execute remote code.");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.70-2ubuntu0.1+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.70-2ubuntu1.24.10.1", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.70-2ubuntu1.25.04.1", rls:"UBUNTU25.04"))) {
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
