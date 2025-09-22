# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845459");
  script_cve_id("CVE-2021-3670", "CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32745", "CVE-2022-32746");
  script_tag(name:"creation_date", value:"2022-08-02 01:00:28 +0000 (Tue, 02 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 18:09:32 +0000 (Mon, 29 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5542-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5542-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5542-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-5542-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Samba did not handle MaxQueryDuration when being
used in AD DC configurations, contrary to expectations. This issue only
affected Ubuntu 20.04 LTS. (CVE-2021-3670)

Luke Howard discovered that Samba incorrectly handled certain restrictions
associated with changing passwords. A remote attacker being requested to
change passwords could possibly use this issue to escalate privileges.
(CVE-2022-2031)

Luca Moro discovered that Samba incorrectly handled certain SMB1
communications. A remote attacker could possibly use this issue to obtain
sensitive memory contents. (CVE-2022-32742)

Joseph Sutton discovered that Samba incorrectly handled certain password
change requests. A remote attacker could use this issue to change passwords
of other users, resulting in privilege escalation. (CVE-2022-32744)

Joseph Sutton discovered that Samba incorrectly handled certain LDAP add or
modify requests. A remote attacker could possibly use this issue to cause
Samba to crash, resulting in a denial of service. (CVE-2022-32745)

Joseph Sutton and Andrew Bartlett discovered that Samba incorrectly handled
certain LDAP add or modify requests. A remote attacker could possibly use
this issue to cause Samba to crash, resulting in a denial of service.
(CVE-2022-32746)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.17~dfsg-0ubuntu1.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.15.9+dfsg-0ubuntu0.2", rls:"UBUNTU22.04 LTS"))) {
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
