# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0339.1");
  script_cve_id("CVE-2018-16839", "CVE-2018-16840", "CVE-2018-16842", "CVE-2018-16890", "CVE-2019-3822", "CVE-2019-3823");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-14 20:12:02 +0000 (Thu, 14 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0339-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190339-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123378");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-February/005111.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2019:0339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

Security issues fixed:

- CVE-2019-3822: Fixed a NTLMv2 type-3 header stack buffer overflow (bsc#1123377).
- CVE-2019-3823: Fixed an out-of-bounds read in the SMTP end-of-response (bsc#1123378).
- CVE-2018-16890: Fixed an out-of-bounds buffer read in NTLM type2 (bsc#1123371).
- CVE-2018-16842: Fixed an out-of-bounds read in tool_msgs.c (bsc#1113660).
- CVE-2018-16840: Fixed a use-after-free in handle close (bsc#1113029).
- CVE-2018-16839: Fixed an SASL password overflow caused by an integer overflow (bsc#1112758).");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.60.0~4.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.60.0~4.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.60.0~4.3.1", rls:"SLES12.0SP4"))) {
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
