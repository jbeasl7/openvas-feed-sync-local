# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0631.1");
  script_cve_id("CVE-2022-21595", "CVE-2022-38791");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 19:35:19 +0000 (Thu, 01 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0631-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0631-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230631-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202863");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/013977.html");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10427-changelog");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10427-release-notes");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10428-changelog");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10428-release-notes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'security update for mariadb' package(s) announced via the SUSE-SU-2023:0631-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

- CVE-2022-38791: Fixed deadlock in compress_write in extra/mariabackup/ds_compress.cc (bsc#1202863).

Version update from 10.4.26 to 10.4.28 (fixes CVE-2022-38791 and CVE-2022-38791).

- Update to 10.4.28:
 * [links moved to references]

- Update list of skipped tests
- Update mariadb.keyring");

  script_tag(name:"affected", value:"'security update for mariadb' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd-devel", rpm:"libmariadbd-devel~10.4.28~150200.3.38.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.4.28~150200.3.38.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.4.28~150200.3.38.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.4.28~150200.3.38.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.4.28~150200.3.38.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.4.28~150200.3.38.1", rls:"SLES15.0SP2"))) {
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
