# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122174");
  script_cve_id("CVE-2011-0010");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:15 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0599)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0599");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0599.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the ELSA-2011-0599 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7.4p5-5]
- patch: log failed user role changes
 Resolves: rhbz#665131

[1.7.4p5-4]
- added #includedir /etc/sudoers.d to sudoers
 Resolves: rhbz#615087

[1.7.4p5-3]
- added !visiblepw option to sudoers
 Resolves: rhbz#688640

[1.7.4p5-2]
- added patch for rhbz#665131
 Resolves: rhbz#665131

[1.7.4p5-1]
- rebase to latest stable version
- sudo now uses /var/db/sudo for timestamps
- new command available: sudoreplay
- use native audit support
- sync configuration paths with the nss_ldap package
 Resolves: rhbz#615087
 Resolves: rhbz#652726
 Resolves: rhbz#634159
 Resolves: rhbz#603823");

  script_tag(name:"affected", value:"'sudo' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.4p5~5.el6", rls:"OracleLinux6"))) {
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
