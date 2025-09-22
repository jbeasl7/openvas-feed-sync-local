# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0246.1");
  script_cve_id("CVE-2017-13720", "CVE-2017-13722", "CVE-2017-16612");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-14 18:20:56 +0000 (Thu, 14 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0246-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180246-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065386");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003648.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2018:0246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-libs fixes several issues.

These security issues were fixed:

- CVE-2017-16612: Heap overflows due to an integer overflow while parsing images and a signedness issue while parsing comments (bsc#1065386).
- CVE-2017-13720: Improper check for end of string in PatterMatch caused invalid reads (bsc#1054285)
- CVE-2017-13722: Malformed PCF file could have caused DoS or leak information (bsc#1049692)
- Prevent the X server from accessing arbitrary files as root. It is not possible to leak information, but special files can be touched allowing for causing side effects (bsc#1050459)");

  script_tag(name:"affected", value:"'xorg-x11-libs' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~7.4~8.26.50.5.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.4~8.26.50.5.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-x86", rpm:"xorg-x11-libs-x86~7.4~8.26.50.5.3", rls:"SLES11.0SP4"))) {
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
