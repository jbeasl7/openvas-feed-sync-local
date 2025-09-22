# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122581");
  script_cve_id("CVE-2007-5962");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:35 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0295)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0295");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0295.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vsftpd' package(s) announced via the ELSA-2008-0295 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.0.5-12]
- fix CVE-2007-5962: vsftpd memory leak when deny_file option is set
- Resolves: #423001

[2.0.5-11]
- add new option to log login failures based on user list
- Resolves: #345791
- fix user_config_dir option
- Resolves: #400921
- allow usernames starting with '_' or '.'
- Resolves: #386561
- fix the write/race condition when uploading files simultaneously
- Resolves: #240553
- fix the bug that causes every new file stored with STOU to have a prefix '.1'
- Resolves: #392231
- make vsftpd wildcard matching more greedy
- Resolves: #392181");

  script_tag(name:"affected", value:"'vsftpd' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~2.0.5~12.el5", rls:"OracleLinux5"))) {
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
