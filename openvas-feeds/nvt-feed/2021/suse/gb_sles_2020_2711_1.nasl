# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2711.1");
  script_cve_id("CVE-2018-18584", "CVE-2018-18585", "CVE-2019-1010305");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 17:10:12 +0000 (Tue, 30 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2711-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2711-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202711-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141680");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007450.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmspack' package(s) announced via the SUSE-SU-2020:2711-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libmspack fixes the following issues:

Security issues fixed:

- CVE-2019-1010305: Fixed a buffer overflow triggered by a crafted chm file
 which could have led to information disclosure (bsc#1141680).
- CVE-2018-18584: The CAB block input buffer was one byte too small for the
 maximal Quantum block, leading to an out-of-bounds write. (bsc#1113038)
- CVE-2018-18585: chmd_read_headers accepted a filename that has '\0' as its
 first or second character (such as the '/\0' name). (bsc#1113039)
- Fix off-by-one bounds check on CHM PMGI/PMGL chunk numbers and reject empty filenames.");

  script_tag(name:"affected", value:"'libmspack' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmspack0", rpm:"libmspack0~0.4~15.7.1", rls:"SLES12.0SP5"))) {
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
