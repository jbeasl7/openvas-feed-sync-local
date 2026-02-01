# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7978.1");
  script_cve_id("CVE-2023-24626", "CVE-2025-46802", "CVE-2025-46804", "CVE-2025-46805");
  script_tag(name:"creation_date", value:"2026-01-27 15:40:12 +0000 (Tue, 27 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 13:23:23 +0000 (Wed, 19 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-7978-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7978-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7978-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'screen' package(s) announced via the USN-7978-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNU Screen incorrectly handled signals when setuid
or setgid privileges were being used, which is not the default in Ubuntu.
A local attacker could use this issue to send privileged signals, possibly
leading to a denial of service. This issue only affected Ubuntu 22.04 LTS.
(CVE-2023-24626)

It was discovered that GNU Screen incorrectly handled PTY permissions. A
local attacker could possibly use this issue to connect to an unauthorized
screen session. (CVE-2025-46802)

It was discovered that GNU Screen incorrectly handled file access when
setuid privileges were being used, which is not the default in Ubuntu. A
local attacker could use this issue to deduce information about certain
file paths. (CVE-2025-46804)

It was discovered that GNU Screen incorrectly handled signals when setuid
privileges were being used, which is not the default in Ubuntu. A local
attacker could use this issue to send privileged signals, possibly leading
to a denial of service. (CVE-2025-46805)");

  script_tag(name:"affected", value:"'screen' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"screen", ver:"4.9.0-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"screen", ver:"4.9.1-1ubuntu1", rls:"UBUNTU24.04 LTS"))) {
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
