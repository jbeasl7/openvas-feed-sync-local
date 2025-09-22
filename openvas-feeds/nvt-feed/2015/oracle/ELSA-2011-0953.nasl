# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122133");
  script_cve_id("CVE-2011-2520");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:36 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 02:53:00 +0000 (Sun, 21 Jan 2024)");

  script_name("Oracle: Security Advisory (ELSA-2011-0953)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0953");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0953.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'system-config-firewall, system-config-printer' package(s) announced via the ELSA-2011-0953 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"system-config-firewall:

[1.2.27-3.3]
- fixed possible privilege escalation flaw via use of python pickle
 (CVE-2011-2520), replaced pickle by json (rhbz#717985)
- stop D-BUS firewall mechanism on update

system-config-printer:

[1.1.16-17:.2]
- Build pycups with -fno-strict-aliasing compiler option to avoid
 compiler warnings.

[1.1.16-17:.1]
- Adapted to system-config-firewall API change (bug #717985, CVE-2011-2520).");

  script_tag(name:"affected", value:"'system-config-firewall, system-config-printer' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"system-config-firewall", rpm:"system-config-firewall~1.2.27~3.el6_1.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-config-firewall-base", rpm:"system-config-firewall-base~1.2.27~3.el6_1.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-config-firewall-tui", rpm:"system-config-firewall-tui~1.2.27~3.el6_1.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-config-printer", rpm:"system-config-printer~1.1.16~17.el6_1.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-config-printer-libs", rpm:"system-config-printer-libs~1.1.16~17.el6_1.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-config-printer-udev", rpm:"system-config-printer-udev~1.1.16~17.el6_1.2", rls:"OracleLinux6"))) {
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
