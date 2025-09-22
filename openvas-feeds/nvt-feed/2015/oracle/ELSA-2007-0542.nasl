# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122640");
  script_cve_id("CVE-2007-4570");
  script_tag(name:"creation_date", value:"2015-10-08 11:49:59 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2007-0542)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0542");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0542.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mcstrans' package(s) announced via the ELSA-2007-0542 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.2.6-1]
- Don't allow categories > 1023
Resolves: #288941

[0.2.3-1]
- Additional fix to handle ssh root/sysadm_r/s0:c1,c2
Resolves: #224637

[0.2.1-1]
- Rewrite to handle MLS properly
Resolves: #225355

[0.1.10-2]
- Cleanup memory when complete

[0.1.10-1]
- Fix Memory Leak
Resolves: #218173

[0.1.9-1]
- Add -pie
- Fix compiler warnings
- Fix Memory Leak
Resolves: #218173

[0.1.8-3]
- Fix subsys locking in init script

[0.1.8-1]
- Only allow one version to run
- rebuild

[0.1.7-1]
- Apply sgrubb patch to only call getpeercon on translations

[0.1.6-1]
- Exit gracefully when selinux is not enabled

[0.1.5-1]
- Fix sighup handling

[0.1.4-1]
- Add patch from sgrubb
- Fix 64 bit size problems
- Increase the open file limit
- Make sure maximum size is not exceeded

[0.1.3-1]
- Move initscripts to /etc/rc.d/init.d

[0.1.2-1]
- Drop Privs

[0.1.1-1]
- Initial Version
- This daemon reuses the code from libsetrans");

  script_tag(name:"affected", value:"'mcstrans' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"mcstrans", rpm:"mcstrans~0.2.6~1.el5", rls:"OracleLinux5"))) {
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
