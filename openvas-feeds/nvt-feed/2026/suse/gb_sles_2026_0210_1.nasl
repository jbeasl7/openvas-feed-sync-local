# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0210.1");
  script_cve_id("CVE-2007-4559", "CVE-2024-12718", "CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4435", "CVE-2025-4517");
  script_tag(name:"creation_date", value:"2026-01-26 08:39:16 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-27T05:49:07+0000");
  script_tag(name:"last_modification", value:"2026-01-27 05:49:07 +0000 (Tue, 27 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0210-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260210-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251841");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023842.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SUSE-SU-2026:0210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-4517: Fixed arbitrary filesystem writes outside the extraction directory during extraction
 with filter='data' (bsc#1244032)
- CVE-2025-4330: Fixed extraction filter bypass for linking outside extraction directory (bsc#1244060)
- CVE-2007-4559: Fixed python tarfile module directory traversal (bsc#1203750)
- CVE-2024-12718: Fixed bypass extraction filter to modify file metadata outside extraction directory
 (bsc#1244056)
- CVE-2025-4138: Fixed symlinking targets to not point outside the destination directory, and the modification
 of some file metadata (bsc#1244059)
- CVE-2025-4435: Fixed tarfile extracting filtered members when errorlevel=0 (bsc#1244061)

Other fixes:

- Fixed two shebangs with /usr/local/bin/python");

  script_tag(name:"affected", value:"'python3' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0-32bit", rpm:"libpython3_4m1_0-32bit~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel", rpm:"python3-devel~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tk", rpm:"python3-tk~3.4.10~25.169.1", rls:"SLES12.0SP5"))) {
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
