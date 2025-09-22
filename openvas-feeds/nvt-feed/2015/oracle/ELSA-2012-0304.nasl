# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123970");
  script_cve_id("CVE-2010-0424");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:59 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0304");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0304.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vixie-cron' package(s) announced via the ELSA-2012-0304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4:4.1-81]
- 455664 adoptions of crontab orphans, forgot add buffer for list of
 orphans
- Related: rhbz#455664

[4:4.1-80]
- 654961 crond process ignores the changes of user's home directory needs
 bigger changes of code. The fix wasn't applied, detail in comment#11.
- Related: rhbz#249512

[4:4.1-79]
- CVE-2010-0424 vixie-cron, cronie: Race condition by setting timestamp
 of user's crontab file, when editing the file
- Resolves: rhbz#741534

[4:4.1-78]
- 625016 - crond requires a restart if mcstransd is stopped
- Resolves: rhbz#625016

[4:4.1-78]
- 460070 entries in cronjobs in /etc/cron.d are checked for valid syntax
- Resolves: rhbz#460070

[4:4.1-78]
- 455664 adoptions of crontab orphans
- 249512 crontab should verify a user's access to PAM cron service
- Resolves: rhbz#455664, rhbz#249512

[4:4.1-78]
- 699621 and 699620 man page fix
- 529632 service crond status return correct status
- 480930 set correct pie options in CFLAGS and LDFLAGS
- 476972 crontab error with @reboot entry
- Resolves: rhbz#699621, rhbz#699620, rhbz#529632, rhbz#480930, rhbz#476972");

  script_tag(name:"affected", value:"'vixie-cron' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"vixie-cron", rpm:"vixie-cron~4.1~81.el5", rls:"OracleLinux5"))) {
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
