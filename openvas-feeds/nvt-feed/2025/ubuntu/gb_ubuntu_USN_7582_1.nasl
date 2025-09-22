# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7582.1");
  script_cve_id("CVE-2022-3437", "CVE-2022-42898", "CVE-2022-45141", "CVE-2023-34966");
  script_tag(name:"creation_date", value:"2025-06-20 04:08:05 +0000 (Fri, 20 Jun 2025)");
  script_version("2025-06-20T05:40:42+0000");
  script_tag(name:"last_modification", value:"2025-06-20 05:40:42 +0000 (Fri, 20 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-13 18:05:10 +0000 (Mon, 13 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-7582-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7582-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7582-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-7582-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evgeny Legerov discovered that Samba incorrectly handled buffers in
certain GSSAPI routines of Heimdal. A remote attacker could possibly use
this issue to cause Samba to crash, resulting in a denial of service.
(CVE-2022-3437)

Greg Hudson discovered that Samba incorrectly handled PAC parsing. On
32-bit systems, a remote attacker could use this issue to escalate
privileges, or possibly execute arbitrary code. (CVE-2022-42898)

Joseph Sutton discovered that Samba could be forced to issue rc4-hmac
encrypted Kerberos tickets. A remote attacker could possibly use this issue
to escalate privileges. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2022-45141)

Florent Saudel discovered that Samba incorrectly handled certain Spotlight
requests. A remote attacker could possibly use this issue to cause Samba to
consume resources, leading to a denial of service. (CVE-2023-34966)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.3.11+dfsg-0ubuntu0.14.04.20+esm13", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.3.11+dfsg-0ubuntu0.16.04.34+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.7.6+dfsg~ubuntu-0ubuntu2.29+esm1", rls:"UBUNTU18.04 LTS"))) {
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
