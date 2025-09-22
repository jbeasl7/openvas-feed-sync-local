# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3389.1");
  script_cve_id("CVE-2017-18233", "CVE-2017-18234", "CVE-2017-18236", "CVE-2017-18238", "CVE-2018-7728", "CVE-2018-7730");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 16:54:06 +0000 (Thu, 05 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3389-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3389-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183389-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085589");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004783.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exempi' package(s) announced via the SUSE-SU-2018:3389-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exempi fixes the following security issues:

- CVE-2017-18233: Prevent integer overflow in the Chunk class that allowed
 remote attackers to cause a denial of service (infinite loop) via crafted XMP
 data in a .avi file (bsc#1085584).
- CVE-2017-18238: The TradQT_Manager::ParseCachedBoxes function allowed remote
 attackers to cause a denial of service (infinite loop) via crafted XMP data in
 a .qt file (bsc#1085583).
- CVE-2018-7728: Fixed heap-based buffer overflow, which allowed denial of
 service via crafted TIFF image (bsc#1085297).
- CVE-2018-7730: Fixed heap-based buffer overflow in
 XMPFiles/source/FormatSupport/PSIR_FileWriter.cpp (bsc#1085295).
- CVE-2017-18236: The ASF_Support::ReadHeaderObject function allowed remote
 attackers to cause a denial of service (infinite loop) via a crafted .asf file
 (bsc#1085589).
- CVE-2017-18234: Prevent use-after-free that allowed remote attackers to cause
 a denial of service or possibly have unspecified other impact via a .pdf file
 containing JPEG data (bsc#1085585).");

  script_tag(name:"affected", value:"'exempi' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libexempi3", rpm:"libexempi3~2.2.1~5.7.1", rls:"SLES12.0SP3"))) {
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
