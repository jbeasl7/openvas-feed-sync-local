# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3083.1");
  script_cve_id("CVE-2019-2894", "CVE-2019-2933", "CVE-2019-2945", "CVE-2019-2949", "CVE-2019-2958", "CVE-2019-2962", "CVE-2019-2964", "CVE-2019-2973", "CVE-2019-2975", "CVE-2019-2977", "CVE-2019-2978", "CVE-2019-2981", "CVE-2019-2983", "CVE-2019-2987", "CVE-2019-2988", "CVE-2019-2989", "CVE-2019-2992", "CVE-2019-2999");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-22 14:54:00 +0000 (Tue, 22 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3083-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3083-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193083-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154212");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006189.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2019:3083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

Security issues fixed (October 2019 CPU bsc#1154212):

- CVE-2019-2933: Windows file handling redux
- CVE-2019-2945: Better socket support
- CVE-2019-2949: Better Kerberos ccache handling
- CVE-2019-2958: Build Better Processes
- CVE-2019-2964: Better support for patterns
- CVE-2019-2962: Better Glyph Images
- CVE-2019-2973: Better pattern compilation
- CVE-2019-2975: Unexpected exception in jjs
- CVE-2019-2978: Improved handling of jar files
- CVE-2019-2977: Improve String index handling
- CVE-2019-2981: Better Path supports
- CVE-2019-2983: Better serial attributes
- CVE-2019-2987: Better rendering of native glyphs
- CVE-2019-2988: Better Graphics2D drawing
- CVE-2019-2989: Improve TLS connection support
- CVE-2019-2992: Enhance font glyph mapping
- CVE-2019-2999: Commentary on Javadoc comments
- CVE-2019-2894: Enhance ECDSA operations (bsc#1152856).");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.5.0~3.3.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.5.0~3.3.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.5.0~3.3.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.5.0~3.3.3", rls:"SLES12.0SP5"))) {
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
