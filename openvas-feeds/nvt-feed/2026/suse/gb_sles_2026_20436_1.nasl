# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20436.1");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59465", "CVE-2025-59466", "CVE-2026-21637", "CVE-2026-22036");
  script_tag(name:"creation_date", value:"2026-02-20 04:36:11 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-03 21:29:50 +0000 (Tue, 03 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20436-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20436-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620436-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256848");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024339.html");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs22' package(s) announced via the SUSE-SU-2026:20436-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs22 fixes the following issues:

Update to 22.22.0:

- CVE-2025-55130: file system permissions bypass via crafted symlinks (bsc#1256569).
- CVE-2025-55131: timeout-based race conditions allow for allocations that contain leftover data from previous operations and lead to exposure of in-process secrets (bsc#1256570).
- CVE-2025-55132: a file's access and modification timestamps can be changed via `futimes()` even when the process has only read permissions (bsc#1256571).
- CVE-2025-59465: malformed HTTP/2 HEADERS frame with invalid HPACK data can cause a crash due to an unhandled error (bsc#1256573).
- CVE-2025-59466: uncatchable 'Maximum call stack size exceeded' error when `async_hooks.createHook()` is enabled can lead to crash (bsc#1256574).
- CVE-2026-21637: synchronous exceptions thrown during certain callbacks bypass the standard TLS error handling paths and can cause a denial of service (bsc#1256576).
- CVE-2026-22036: undici: unbounded decompression chain in HTTP responses via Content-Encoding may lead to resource exhaustion (bsc#1256848).

For full changelog, please see [link moved to references]");

  script_tag(name:"affected", value:"'nodejs22' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"corepack22", rpm:"corepack22~22.22.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22", rpm:"nodejs22~22.22.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-devel", rpm:"nodejs22-devel~22.22.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-docs", rpm:"nodejs22-docs~22.22.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm22", rpm:"npm22~22.22.0~160000.1.1", rls:"SLES16.0.0"))) {
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
