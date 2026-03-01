# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0435.1");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59465", "CVE-2025-59466", "CVE-2026-21637", "CVE-2026-22036");
  script_tag(name:"creation_date", value:"2026-02-13 04:40:02 +0000 (Fri, 13 Feb 2026)");
  script_version("2026-02-13T05:57:48+0000");
  script_tag(name:"last_modification", value:"2026-02-13 05:57:48 +0000 (Fri, 13 Feb 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-03 21:29:50 +0000 (Tue, 03 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0435-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260435-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256848");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024113.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the SUSE-SU-2026:0435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs20 fixes the following issues:

- Update to 20.20.0:
- CVE-2026-22036: Updated undici to 6.23.0 (bsc#1256848)
- CVE-2025-59465: Add TLSSocket default error handler (bsc#1256573)
- CVE-2025-55132: Disable futimes when permission model is enabled (bsc#1256571)
- CVE-2025-55130: Require full read and write to symlink APIs (bsc#1256569)
- CVE-2025-59466: Rethrow stack overflow exceptions in async_hooks (bsc#1256574)
- CVE-2025-55131: Refactor unsafe buffer creation to remove zero-fill toggle (bsc#1256570)
- CVE-2026-21637: Route callback exceptions through error handlers (bsc#1256576)");

  script_tag(name:"affected", value:"'nodejs20' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"corepack20", rpm:"corepack20~20.20.0~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.20.0~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.20.0~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.20.0~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm20", rpm:"npm20~20.20.0~150600.3.15.1", rls:"openSUSELeap15.6"))) {
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
