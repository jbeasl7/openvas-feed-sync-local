# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7705.1");
  script_cve_id("CVE-2024-50379", "CVE-2024-52317", "CVE-2024-54677", "CVE-2025-31650", "CVE-2025-31651", "CVE-2025-46701");
  script_tag(name:"creation_date", value:"2025-08-20 10:27:17 +0000 (Wed, 20 Aug 2025)");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-05 20:14:47 +0000 (Mon, 05 May 2025)");

  script_name("Ubuntu: Security Advisory (USN-7705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7705-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7705-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10' package(s) announced via the USN-7705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat did not correctly handle case sensitivity.
An attacker could possibly use this issue to bypass authentication
mechanisms. (CVE-2025-46701)

Elysee Franchuk discovered that Tomcat did not correctly limit the number
of attributes for a session. An attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 24.04 LTS.
(CVE-2024-54677)

It was discovered that Tomcat did not correctly sanitize certain URLs. An
attacker could possibly use this issue to bypass authentication
mechanisms. (CVE-2025-31651)

It was discovered that Tomcat did not correctly handle certain malformed
HTTP headers,
which could lead to a memory leak. An attacker could possibly use this
issue to cause a denial of service. This issue only affected
Ubuntu 24.04 LTS. (CVE-2025-31650)

It was discovered that Tomcat did not correctly handle concurrent
operations under certain circumstances. An attacker could possibly use
this issue to execute arbitrary code. This issue only affected
Ubuntu 24.04 LTS. (CVE-2024-50379)

It was discovered that Tomcat did not correctly handle certain
authentication errors. An attacker could possibly use this issue to
bypass authentication mechanisms. This issue only affected
Ubuntu 24.04 LTS. (CVE-2024-52316)");

  script_tag(name:"affected", value:"'tomcat10' package(s) on Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat10-java", ver:"10.1.16-1ubuntu0.1~esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10", ver:"10.1.16-1ubuntu0.1~esm3", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat10-java", ver:"10.1.35-1ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat10", ver:"10.1.35-1ubuntu0.1", rls:"UBUNTU25.04"))) {
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
