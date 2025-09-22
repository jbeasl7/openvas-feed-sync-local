# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7520.2");
  script_cve_id("CVE-2025-4207");
  script_tag(name:"creation_date", value:"2025-05-22 04:06:08 +0000 (Thu, 22 May 2025)");
  script_version("2025-05-22T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-22 05:40:21 +0000 (Thu, 22 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7520-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU25\.04");

  script_xref(name:"Advisory-ID", value:"USN-7520-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7520-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-17' package(s) announced via the USN-7520-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7520-1 fixed a vulnerability in PostgreSQL. This update provides the
corresponding updates for Ubuntu 25.04.

Original advisory details:

 It was discovered that PostgreSQL incorrectly handled the GB18030
 encoding. An attacker could possibly use this issue to cause PostgreSQL to
 crash, resulting in a denial of service.");

  script_tag(name:"affected", value:"'postgresql-17' package(s) on Ubuntu 25.04.");

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

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-17", ver:"17.5-0ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-17", ver:"17.5-0ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
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
