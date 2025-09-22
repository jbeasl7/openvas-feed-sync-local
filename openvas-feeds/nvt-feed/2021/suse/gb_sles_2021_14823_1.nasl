# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14823.1");
  script_cve_id("CVE-2019-14275", "CVE-2019-19555", "CVE-2019-19746", "CVE-2019-19797", "CVE-2020-21680", "CVE-2020-21681", "CVE-2020-21682", "CVE-2020-21683", "CVE-2021-3561");
  script_tag(name:"creation_date", value:"2021-10-07 14:57:43 +0000 (Thu, 07 Oct 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 17:43:23 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14823-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14823-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114823-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189346");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009541.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'transfig' package(s) announced via the SUSE-SU-2021:14823-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for transfig fixes the following issues:

- CVE-2021-3561: Fixed global buffer overflow in fig2dev/read.c in function read_colordef() (bsc#1186329).
- CVE-2019-19797: Fixed out-of-bounds write in read_colordef in read.c (bsc#1159293).
- CVE-2019-19746: Fixed segmentation fault and out-of-bounds write because of an integer overflow via a large arrow type (bsc#1159130).
- CVE-2019-19555: Fixed stack-based buffer overflow because of an incorrect sscanf (bsc#1161698).
- CVE-2019-14275: Fixed stack-based buffer overflow in the calc_arrow function in bound.c (bsc#1143650).
- CVE-2020-21680: Fixed a stack-based buffer overflow in the put_arrow() component in genpict2e.c (bsc#1189343).
- CVE-2020-21681: Fixed a global buffer overflow in the set_color component in genge.c (bsc#1189345).
- CVE-2020-21682: Fixed a global buffer overflow in the set_fill component in genge.c (bsc#1189346).
- CVE-2020-21683: Fixed a global buffer overflow in the shade_or_tint_name_after_declare_color in genpstricks.c (bsc#1189325).

- Do hardening via compile and linker flags
- Fixed last added upstream commit (boo#1136882)");

  script_tag(name:"affected", value:"'transfig' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.8a~1.160.13.1", rls:"SLES11.0SP4"))) {
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
