# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2911.1");
  script_cve_id("CVE-2015-2304", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-21 18:57:24 +0000 (Wed, 21 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2911-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2911-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162911-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998677");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002421.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SUSE-SU-2016:2911-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libarchive fixes several issues.

These security issues were fixed:

- CVE-2016-8687: Buffer overflow when printing a filename (bsc#1005070).
- CVE-2016-8689: Heap overflow when reading corrupted 7Zip files (bsc#1005072).
- CVE-2016-8688: Use after free because of incorrect calculation in next_line (bsc#1005076).
- CVE-2016-5844: Integer overflow in the ISO parser in libarchive allowed remote attackers to cause a denial of service (application crash) via a crafted ISO file (bsc#986566).
- CVE-2016-6250: Integer overflow in the ISO9660 writer in libarchive allowed remote attackers to cause a denial of service (application crash) or execute arbitrary code via vectors related to verifying filename lengths when writing an ISO9660 archive, which trigger a buffer overflow (bsc#989980).
- CVE-2016-5418: The sandboxing code in libarchive mishandled hardlink archive entries of non-zero data size, which might allowed remote attackers to write to arbitrary files via a crafted archive file (bsc#998677).");

  script_tag(name:"affected", value:"'libarchive' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.1.2~25.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.1.2~25.1", rls:"SLES12.0SP2"))) {
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
