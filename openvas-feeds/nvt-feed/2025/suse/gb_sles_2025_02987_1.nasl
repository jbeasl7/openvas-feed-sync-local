# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02987.1");
  script_cve_id("CVE-2025-8713", "CVE-2025-8714", "CVE-2025-8715");
  script_tag(name:"creation_date", value:"2025-08-28 04:10:48 +0000 (Thu, 28 Aug 2025)");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02987-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02987-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502987-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248122");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041361.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql17' package(s) announced via the SUSE-SU-2025:02987-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql17 fixes the following issues:

Updated to 17.6:
 * CVE-2025-8713: Fixed optimizer statistics exposing
 sampled data within a view, partition, or child table
 (bsc#1248120)
 * CVE-2025-8714: Fixed untrusted data inclusion in pg_dump
 allows superuser of origin server to execute arbitrary code
 in psql client (bsc#1248122)
 * CVE-2025-8715: Fixed improper neutralization of newlines
 in pg_dump leading to arbitrary code execution in the psql
 client and in the restore target server (bsc#1248119)");

  script_tag(name:"affected", value:"'postgresql17' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~17.6~3.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~17.6~3.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~17.6~3.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~17.6~3.16.1", rls:"SLES12.0SP5"))) {
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
