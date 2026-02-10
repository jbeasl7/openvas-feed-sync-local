# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20214.1");
  script_cve_id("CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881", "CVE-2025-68156");
  script_tag(name:"creation_date", value:"2026-02-09 04:44:52 +0000 (Mon, 09 Feb 2026)");
  script_version("2026-02-09T06:03:20+0000");
  script_tag(name:"last_modification", value:"2026-02-09 06:03:20 +0000 (Mon, 09 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-03 18:30:15 +0000 (Wed, 03 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20214-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20214-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620214-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255333");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'alloy' package(s) announced via the SUSE-SU-2026:20214-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-68156: github.com/expr-lang/expr/builtin: Fixed potential DoS via unbounded recursion (bsc#1255333):
- CVE-2025-31133, CVE-2025-52565, CVE-2025-52881: github.com/opencontainers/runc: Fixed container
 breakouts by bypassing runc's restrictions for writing to arbitrary /proc files (bsc#1255074)

Other fixes:

 - Add missing configuration parameter
 deployment_name_from_replicaset to k8sattributes processor
 (5b90a9d) (@dehaansa)
 - database_observability: Fix schema_details collector to fetch
 column definitions with case sensitive table names (#4872)
 (560dff4) (@jharvey10, @fridgepoet)
 - deps: Update jose2go to 1.7.0 (#4858) (dfdd341) (@jharvey10)
 - deps: Update npm dependencies [backport] (#5201) (8e06c26)
 (@jharvey10)
 - Ensure the squid exporter wrapper properly brackets ipv6
 addresses [backport] (#5205) (e329cc6) (@dehaansa)
 - Preserve meta labels in loki.source.podlogs (#5097) (ab4b21e)
 (@kalleep)
 - Prevent panic in import.git when update fails [backport]
 (#5204) (c82fbae) (@dehaansa, @jharvey10)
 - show correct fallback alloy version instead of v1.13.0
 (#5110) (b72be99) (@dehaansa, @jharvey10)");

  script_tag(name:"affected", value:"'alloy' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"alloy", rpm:"alloy~1.12.2~160000.1.1", rls:"SLES16.0.0"))) {
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
