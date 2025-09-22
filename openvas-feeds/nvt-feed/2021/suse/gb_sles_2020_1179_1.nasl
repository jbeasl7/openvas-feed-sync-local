# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1179.1");
  script_cve_id("CVE-2019-18904");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-06 16:18:39 +0000 (Mon, 06 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1179-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201179-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168554");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-May/006778.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2020:1179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rmt-server to version 2.5.7 fixes the following issues:

Security issues fixed:

- CVE-2019-18904: Fixed offline migrations (bsc#1160922).
- Fixed a local denial of service (bsc#1165548).

Non-security issues fixed:

- Align supported subscription types with SCC (bsc#1168554).
- Fix migrations in case adding migration_extra column failed (bsc#1162296).
- Fix dependency to removed boot_cli_i18n file (bsc#1136020)");

  script_tag(name:"affected", value:"'rmt-server' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"rmt-server", rpm:"rmt-server~2.5.7~3.31.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-config", rpm:"rmt-server-config~2.5.7~3.31.1", rls:"SLES15.0"))) {
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
