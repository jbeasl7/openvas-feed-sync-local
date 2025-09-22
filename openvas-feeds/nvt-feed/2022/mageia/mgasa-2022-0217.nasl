# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0217");
  script_cve_id("CVE-2022-1348");
  script_tag(name:"creation_date", value:"2022-06-06 04:33:17 +0000 (Mon, 06 Jun 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 19:04:41 +0000 (Tue, 07 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0217)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0217");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0217.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30473");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5447-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/05/25/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/05/25/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'logrotate' package(s) announced via the MGASA-2022-0217 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in logrotate in how the state file is created.
The state file is used to prevent parallel executions of multiple instances
of logrotate by acquiring and releasing a file lock. When the state file
does not exist, it is created with world-readable permission, allowing an
unprivileged user to lock the state file, stopping any rotation. This flaw
affects logrotate versions before 3.20.0. (CVE-2022-1348)
Note the change in permission does not apply until the first time logrotate
runs after installing the update.");

  script_tag(name:"affected", value:"'logrotate' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"logrotate", rpm:"logrotate~3.17.0~3.1.mga8", rls:"MAGEIA8"))) {
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
