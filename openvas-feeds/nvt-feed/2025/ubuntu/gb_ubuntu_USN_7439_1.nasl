# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7439.1");
  script_cve_id("CVE-2023-48183", "CVE-2023-48184", "CVE-2024-33263");
  script_tag(name:"creation_date", value:"2025-04-16 04:04:10 +0000 (Wed, 16 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7439-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7439-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7439-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quickjs' package(s) announced via the USN-7439-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that QuickJS could be forced to reference uninitialized
memory in certain instances. An attacker could possibly use this issue to
cause QuickJS to crash, resulting in a denial of service, or execute
arbitrary code. (CVE-2023-48183)

It was discovered that QuickJS incorrectly managed memory in certain
circumstances. An attacker could possibly use this issue to exhaust
system resources, resulting in a denial of service. (CVE-2023-48184)

It was discovered that QuickJS could be forced to crash due to a
failing test. An attacker could possibly use this issue to cause a
denial of service. (CVE-2024-33263)");

  script_tag(name:"affected", value:"'quickjs' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libquickjs", ver:"2021.03.27-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quickjs", ver:"2021.03.27-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
