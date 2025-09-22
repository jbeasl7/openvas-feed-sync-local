# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02201.1");
  script_cve_id("CVE-2025-20234", "CVE-2025-20260");
  script_tag(name:"creation_date", value:"2025-07-04 04:13:06 +0000 (Fri, 04 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-18 18:15:23 +0000 (Wed, 18 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02201-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502201-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245055");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040595.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2025:02201-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

ClamAV version 1.4.3:

- CVE-2025-20260: PDF Scanning Buffer Overflow Vulnerability (bsc#1245054).
- CVE-2025-20234: Vulnerability in Universal Disk Format (UDF) processing (bsc#1245055).

Other bugfixes:

- Fix a race condition between the mockup servers started by different test cases in freshclam_test.py (bsc#1243565)");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-docs-html", rpm:"clamav-docs-html~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav12", rpm:"libclamav12~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam3", rpm:"libfreshclam3~1.4.3~3.47.1", rls:"SLES12.0SP5"))) {
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
