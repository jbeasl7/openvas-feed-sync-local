# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123752");
  script_cve_id("CVE-2011-4339");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0123");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0123.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenIPMI' package(s) announced via the ELSA-2013-0123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.0.16-16.el5]
- ipmitool: fix ipmi command retry shifts replies (#863310)

[2.0.16-15.el5]
- ipmitool: added -b, -B, -l and -T options to ipmitool man page
 (#846596)
- ipmitool: fixed man page documentation for delloem setled command
 (#797050)

[2.0.16-14.el5]
- ipmitool: fixed wrong permissions on ipmievd.pid (#834190)

[2.0.16-13.el5]
- ipmitool: updated delloem commands (#797050)
- ipmitool: fixed exit code of 'ipmitool -o list' command (#740780)
- ipmitool: disabled automatic bridging of SDR readings to IPMB
 in verbose mode (#749796)
- ipmitool: fixed reporting of usage of various delloem subcommands
 (#658762)
- added path to /sbin to lsmod and modprobe (#829705)");

  script_tag(name:"affected", value:"'OpenIPMI' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI", rpm:"OpenIPMI~2.0.16~16.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-devel", rpm:"OpenIPMI-devel~2.0.16~16.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-gui", rpm:"OpenIPMI-gui~2.0.16~16.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-libs", rpm:"OpenIPMI-libs~2.0.16~16.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-perl", rpm:"OpenIPMI-perl~2.0.16~16.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python", rpm:"OpenIPMI-python~2.0.16~16.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-tools", rpm:"OpenIPMI-tools~2.0.16~16.el5", rls:"OracleLinux5"))) {
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
