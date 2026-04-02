# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0892.1");
  script_cve_id("CVE-2021-42380", "CVE-2023-42363", "CVE-2023-42364", "CVE-2023-42365", "CVE-2025-46394", "CVE-2025-60876", "CVE-2026-26157", "CVE-2026-26158");
  script_tag(name:"creation_date", value:"2026-03-16 04:55:27 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 00:38:27 +0000 (Wed, 17 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0892-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260892-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258167");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024690.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2026:0892-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

- CVE-2023-42363: use-after-free vulnerability in xasprintf function in xfuncs_printf.c (bsc#1217580).
- CVE-2023-42364: use-after-free in the awk.c evaluate function (bsc#1217584).
- CVE-2023-42365: use-after-free in the awk.c copyvar function (bsc#1217585).
- CVE-2025-46394: files in a TAR archive can have their filenames hidden from a listing if terminal escape sequences are
 used when naming other files included in the archive (bsc#1241661).
- CVE-2025-60876: request line incorrectly neutralized mat lead to header injection (bsc#1253245).
- CVE-2026-26157: Arbitrary file overwrite and potential code execution via incomplete path sanitization (bsc#1258163).
- CVE-2026-26158: Arbitrary file modification and privilege escalation via unvalidated tar archive entries
 (bsc#1258167).
- CVE-2021-42380: Additional fix for use-after-realloc in awk (bsc#1192869).");

  script_tag(name:"affected", value:"'busybox' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~10.3.1", rls:"SLES12.0SP5"))) {
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
