# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20425.1");
  script_cve_id("CVE-2025-53643", "CVE-2025-69223", "CVE-2025-69224", "CVE-2025-69225", "CVE-2025-69226", "CVE-2025-69227", "CVE-2025-69228", "CVE-2025-69229");
  script_tag(name:"creation_date", value:"2026-02-20 04:36:11 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-14 19:17:21 +0000 (Wed, 14 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20425-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20425-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620425-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256023");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024346.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Brotli, python-aiohttp' package(s) announced via the SUSE-SU-2026:20425-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-aiohttp, python-Brotli fixes the following issues:

Changes in python-aiohttp:

- CVE-2025-69228: Fixed denial of service through large payloads (bsc#1256022).
- CVE-2025-69226: Fixed brute-force leak of internal static file path components (bsc#1256020).
- CVE-2025-69224: Fixed unicode processing of header values could cause parsing discrepancies (bsc#1256018).
- CVE-2025-69223: Fixed aiohttp HTTP Parser auto_decompress feature susceptible to zip bomb (bsc#1256017).
- CVE-2025-69227: Fixed DoS when bypassing asserts (bsc#1256021).
- CVE-2025-69225: Fixed unicode match groups in regexes for ASCII protocol elements (bsc#1256019).
- CVE-2025-69229: Fixed DoS through chunked messages (bsc#1256023).
- CVE-2025-53643: Fixed request smuggling due to incorrect parsing of chunked trailer section (bsc#1246517).

Changes in python-Brotli:

- Add max length decompression (bsc#1254867, bsc#1256017).");

  script_tag(name:"affected", value:"'python-Brotli, python-aiohttp' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"python313-Brotli", rpm:"python313-Brotli~1.1.0~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-aiohttp", rpm:"python313-aiohttp~3.11.16~160000.3.1", rls:"SLES16.0.0"))) {
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
