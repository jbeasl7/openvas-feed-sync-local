# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02297.1");
  script_cve_id("CVE-2024-12718", "CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4435", "CVE-2025-4516", "CVE-2025-4517", "CVE-2025-6069");
  script_tag(name:"creation_date", value:"2025-07-15 04:22:53 +0000 (Tue, 15 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02297-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502297-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244705");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040698.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python36' package(s) announced via the SUSE-SU-2025:02297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python36 fixes the following issues:

- CVE-2024-12718: Fixed extraction filter bypass that allowed file metadata modification outside extraction directory (bsc#1244056)
- CVE-2025-4138: Fixed issue that might allow symlink targets to point outside the destination directory, and the modification of some file metadata (bsc#1244059)
- CVE-2025-4330: Fixed extraction filter bypass that allowed linking outside extraction directory (bsc#1244060)
- CVE-2025-4435: Fixed Tarfile extracts filtered members when errorlevel=0 (bsc#1244061)
- CVE-2025-4516: Fixed denial of service due to DecodeError handling vulnerability (bsc#1243273)
- CVE-2025-4517: Fixed arbitrary filesystem writes outside the extraction directory during extraction with filter='data' (bsc#1244032)
- CVE-2025-6069: Fixed worst case quadratic complexity when processing certain crafted malformed inputs with HTMLParser (bsc#1244705)

Other fixes:
- Add python36-* provides/obsoletes to enable SLE-12 -> SLE-15
 migration (bsc#1233012)
- Update vendored ipaddress module to 3.8 equivalent
- Limit buffer size for IPv6 address parsing (bsc#1244401).");

  script_tag(name:"affected", value:"'python36' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0", rpm:"libpython3_6m1_0~3.6.15~84.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_6m1_0-32bit", rpm:"libpython3_6m1_0-32bit~3.6.15~84.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python36", rpm:"python36~3.6.15~84.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python36-base", rpm:"python36-base~3.6.15~84.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python36-devel", rpm:"python36-devel~3.6.15~84.1", rls:"SLES12.0SP5"))) {
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
