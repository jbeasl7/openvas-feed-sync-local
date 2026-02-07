# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8012.1");
  script_cve_id("CVE-2024-53858", "CVE-2024-54132");
  script_tag(name:"creation_date", value:"2026-02-06 04:34:56 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-8012-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8012-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gh' package(s) announced via the USN-8012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GitHub CLI could behave unexpectedly if users
downloaded a malicious GitHub Actions workflow artifact through gh run
download. An attacker could possibly use this issue to create or overwrite
files in unintended directories. (CVE-2024-54132)

It was discovered that GitHub CLI could behave unexpectedly when cloning
repositories containing git submodules hosted outside of GitHub.com and
ghe.com. An attacker could possibly use this issue to gather authentication
tokens. (CVE-2024-53858)");

  script_tag(name:"affected", value:"'gh' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gh", ver:"2.45.0-1ubuntu0.3+esm2", rls:"UBUNTU24.04 LTS"))) {
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
