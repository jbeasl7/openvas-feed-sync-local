# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0674.1");
  script_cve_id("CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1988", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2003", "CVE-2013-2063", "CVE-2013-6462", "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211", "CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0674-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0674-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150674-1.html");
  script_xref(name:"URL", value:"http://lists.x.org/archives/xorg-announce/2014-May/002431.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921978");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001332.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2015:0674-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xorg-x11-libs was patched to fix the following security issues:

 * Integer overflow of allocations in font metadata file parsing.
 (CVE-2014-0209)
 * libxfont not validating length fields when parsing xfs protocol
 replies. (CVE-2014-0210)
 * Integer overflows causing miscalculating memory needs for xfs
 replies. (CVE-2014-0211)

Further information is available at
[link moved to references]
<[link moved to references]> .

Security Issues references:

 * CVE-2014-0209
 <[link moved to references]>
 * CVE-2014-0210
 <[link moved to references]>
 * CVE-2014-0211
 <[link moved to references]>");

  script_tag(name:"affected", value:"'xorg-x11-libs' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~7.4~8.26.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.4~8.26.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libs-x86", rpm:"xorg-x11-libs-x86~7.4~8.26.42.1", rls:"SLES11.0SP3"))) {
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
