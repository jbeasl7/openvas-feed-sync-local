# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123881");
  script_cve_id("CVE-2011-4623");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0796)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0796");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0796.html");
  script_xref(name:"URL", value:"http://blog.gerhards.net/2012/01/rsyslog-licensing-update.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsyslog' package(s) announced via the ELSA-2012-0796 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.8.10-2]
- add patch to update information on debugging in the man page
 Resolves: #820311
- add patch to prevent debug output to stdout after forking
 Resolves: #820996
- add patch to support ssl certificates with domain names longer than 128 chars
 Resolves: #822118

[5.8.10-1]
- rebase to rsyslog 5.8.10
 Resolves: #803550
 Resolves: #805424
 Resolves: #813079
 Resolves: #813084
- consider lock file in 'status' action
 Resolves: #807608
- add impstats and imptcp modules
- include new license text files
- specify which versions of sysklogd are obsoleted

[5.8.7-1]
- rebase to rsyslog-5.8.7
 - change license from 'GPLv3+' to '(GPLv3+ and ASL 2.0)'
 [link moved to references]
 - remove patches obsoleted by rebase
 - add patches for better sysklogd compatibility (taken from upstream)
 - update included files for the new major version
 Resolves: #672182
 Resolves: #727380
 Resolves: #756664
 Resolves: #767527
 Resolves: #769025
- add several directories for storing auxiliary data
 Resolves: #740420
- fix source package URL");

  script_tag(name:"affected", value:"'rsyslog' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~5.8.10~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-gnutls", rpm:"rsyslog-gnutls~5.8.10~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-gssapi", rpm:"rsyslog-gssapi~5.8.10~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-mysql", rpm:"rsyslog-mysql~5.8.10~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-pgsql", rpm:"rsyslog-pgsql~5.8.10~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-relp", rpm:"rsyslog-relp~5.8.10~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-snmp", rpm:"rsyslog-snmp~5.8.10~2.el6", rls:"OracleLinux6"))) {
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
