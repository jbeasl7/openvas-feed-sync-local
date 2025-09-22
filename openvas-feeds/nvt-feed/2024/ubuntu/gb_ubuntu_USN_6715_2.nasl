# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6715.2");
  script_cve_id("CVE-2024-1013");
  script_tag(name:"creation_date", value:"2024-06-06 04:07:45 +0000 (Thu, 06 Jun 2024)");
  script_version("2025-03-25T05:38:56+0000");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-24 13:02:51 +0000 (Mon, 24 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-6715-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6715-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6715-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unixodbc' package(s) announced via the USN-6715-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6715-1 fixed a vulnerability in unixODBC. This update provides the
corresponding fix for Ubuntu 24.04 LTS.

Original advisory details:

 It was discovered that unixODBC incorrectly handled certain bytes.
 An attacker could use this issue to execute arbitrary code or cause
 a crash.");

  script_tag(name:"affected", value:"'unixodbc' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libodbc2", ver:"2.3.12-1ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unixodbc", ver:"2.3.12-1ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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
