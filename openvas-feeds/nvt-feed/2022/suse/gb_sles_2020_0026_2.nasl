# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0026.2");
  script_cve_id("CVE-2019-19725");
  script_tag(name:"creation_date", value:"2022-07-05 04:34:59 +0000 (Tue, 05 Jul 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-13 20:06:47 +0000 (Fri, 13 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0026-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0026-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200026-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159104");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-July/011392.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sysstat' package(s) announced via the SUSE-SU-2020:0026-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sysstat fixes the following issues:

Security issue fixed:

- CVE-2019-19725: Fixed double free in check_file_actlst in sa_common.c (bsc#1159104).

Bug fixes:

- Enable log information of starting/stoping services. (bsc#1144923, jsc#SLE-5958)");

  script_tag(name:"affected", value:"'sysstat' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"sysstat", rpm:"sysstat~12.0.2~10.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysstat-isag", rpm:"sysstat-isag~12.0.2~10.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"sysstat", rpm:"sysstat~12.0.2~10.36.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysstat-isag", rpm:"sysstat-isag~12.0.2~10.36.1", rls:"SLES12.0SP3"))) {
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
