# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856184");
  script_cve_id("CVE-2024-4317");
  script_tag(name:"creation_date", value:"2024-06-05 01:00:54 +0000 (Wed, 05 Jun 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 16:17:31 +0000 (Wed, 12 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1777-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241777-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224051");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-May/018600.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/15.7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql15' package(s) announced via the SUSE-SU-2024:1777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql15 fixes the following issues:

PostgreSQL upgrade to version 15.7 (bsc#1224051):

- CVE-2024-4317: Fixed visibility restriction of pg_stats_ext and pg_stats_ext_exprs entries to the table owner (bsc#1224038).

Bug fixes:

- Fix incompatibility with LLVM 18.
- Prepare for PostgreSQL 17.
- Make sure all compilation and doc generation happens in %build.
- Require LLVM <= 17 for now, because LLVM 18 doesn't seem to work.
- Remove constraints file because improved memory usage for s390x
- Use %patch -P N instead of deprecated %patchN.

Release notes:

- [link moved to references]");

  script_tag(name:"affected", value:"'postgresql15' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel", rpm:"postgresql15-devel~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-llvmjit", rpm:"postgresql15-llvmjit~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-llvmjit-devel", rpm:"postgresql15-llvmjit-devel~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-devel", rpm:"postgresql15-server-devel~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-test", rpm:"postgresql15-test~15.7~150200.5.27.1", rls:"openSUSELeap15.5"))) {
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
