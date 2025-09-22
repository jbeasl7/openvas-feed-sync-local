# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01767.1");
  script_cve_id("CVE-2025-4207");
  script_tag(name:"creation_date", value:"2025-06-02 04:13:16 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01767-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01767-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501767-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242931");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039449.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/16.9/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql16' package(s) announced via the SUSE-SU-2025:01767-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql16 fixes the following issues:

Upgrade to 16.9:

 - CVE-2025-4207: Fixed PostgreSQL GB18030 encoding validation can read one byte past end of allocation for text that fails validation (bsc#1242931)

Changelog:

[link moved to references]");

  script_tag(name:"affected", value:"'postgresql16' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-contrib", rpm:"postgresql16-contrib~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-devel", rpm:"postgresql16-devel~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-docs", rpm:"postgresql16-docs~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plperl", rpm:"postgresql16-plperl~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-plpython", rpm:"postgresql16-plpython~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pltcl", rpm:"postgresql16-pltcl~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server", rpm:"postgresql16-server~16.9~3.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-server-devel", rpm:"postgresql16-server-devel~16.9~3.29.1", rls:"SLES12.0SP5"))) {
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
