# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1068.1");
  script_cve_id("CVE-2026-3172");
  script_tag(name:"creation_date", value:"2026-03-30 04:58:33 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1068-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261068-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258945");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024941.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgvector' package(s) announced via the SUSE-SU-2026:1068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pgvector fixes the following issue:

Update to pgvector 0.8.2:

- CVE-2026-3172: Buffer overflow in parallel HNSW index build (bsc#1258945).

Changelog:

 * Fixed Index Searches in EXPLAIN output for Postgres 18");

  script_tag(name:"affected", value:"'pgvector' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"pgvector-devel", rpm:"pgvector-devel~0.8.2~150600.13.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-pgvector", rpm:"postgresql16-pgvector~0.8.2~150600.13.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-pgvector", rpm:"postgresql17-pgvector~0.8.2~150600.13.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-pgvector", rpm:"postgresql18-pgvector~0.8.2~150600.13.9.1", rls:"SLES15.0SP6"))) {
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
