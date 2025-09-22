# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7530.1");
  script_cve_id("CVE-2025-46337");
  script_tag(name:"creation_date", value:"2025-05-30 04:05:41 +0000 (Fri, 30 May 2025)");
  script_version("2025-05-30T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-05-30 05:40:08 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7530-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7530-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7530-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libphp-adodb' package(s) announced via the USN-7530-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ADOdb incorrectly handled SQL input. A remote
attacker could use this issue to execute arbitrary SQL commands.");

  script_tag(name:"affected", value:"'libphp-adodb' package(s) on Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libphp-adodb", ver:"5.22.7-0.1ubuntu0.1", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libphp-adodb", ver:"5.22.8-0.1ubuntu0.1", rls:"UBUNTU25.04"))) {
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
