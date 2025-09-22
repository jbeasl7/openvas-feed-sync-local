# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2902.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2902-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182902-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977043");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004615.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yast2-smt' package(s) announced via the SUSE-SU-2018:2902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues in yast2-smt:

- Explicitly mention 'Organization Credentials' (fate#321759)
- Rearrange the SMT set-up dialog (bsc#977043)
- Added missing translation marks (bsc#1037811)
- Remove cron job rescheduling (bsc#1097560)

This update is a requirement for the security update for SMT. Because of that it is tagged as security to ensure that all users, even those that only install security updates,
install it.");

  script_tag(name:"affected", value:"'yast2-smt' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"yast2-smt", rpm:"yast2-smt~3.0.14~17.3.2", rls:"SLES12.0SP2"))) {
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
