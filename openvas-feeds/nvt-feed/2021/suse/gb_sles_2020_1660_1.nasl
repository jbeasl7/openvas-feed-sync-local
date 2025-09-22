# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1660.1");
  script_cve_id("CVE-2017-9670", "CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-18 15:15:18 +0000 (Tue, 18 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1660-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1660-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201660-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117465");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006967.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnuplot' package(s) announced via the SUSE-SU-2020:1660-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnuplot fixes the following issues:

Following security issues were fixed:

- CVE-2018-19492: Fixed a buffer overflow in cairotrm_options function (bsc#1117463)
- CVE-2018-19491: Fixed a buffer overlow in the PS_options function (bsc#1117464)
- CVE-2018-19490: Fixed a heap-based buffer overflow in the df_generate_ascii_array_entry function (bsc#1117465)
- CVE-2017-9670: Fixed a uninitialized stack variable vulnerability which could lead to a Denial of Service (bsc#1044638)");

  script_tag(name:"affected", value:"'gnuplot' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnuplot", rpm:"gnuplot~4.6.5~3.3.74", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gnuplot", rpm:"gnuplot~4.6.5~3.3.74", rls:"SLES12.0SP5"))) {
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
