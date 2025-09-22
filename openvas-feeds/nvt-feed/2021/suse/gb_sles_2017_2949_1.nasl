# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2949.1");
  script_cve_id("CVE-2016-7530", "CVE-2017-11446", "CVE-2017-11534", "CVE-2017-12428", "CVE-2017-12431", "CVE-2017-12433", "CVE-2017-13133", "CVE-2017-13139", "CVE-2017-15033");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-25 15:05:11 +0000 (Fri, 25 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2949-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2949-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172949-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061873");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003381.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2017:2949-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

Security issues fixed:

* CVE-2017-15033: A denial of service attack (memory leak) was fixed in ReadYUVImage in coders/yuv.c [bsc#1061873]
* CVE-2017-11446: An infinite loop in ReadPESImage was fixed. (bsc#1049379)
* CVE-2017-12433: A memory leak in ReadPESImage in coders/pes.c was fixed. (bsc#1052545)
* CVE-2017-12428: A memory leak in ReadWMFImage in coders/wmf.c was fixed. (bsc#1052249)
* CVE-2017-12431: A use-after-free in ReadWMFImage was fixed. (bsc#1052253)
* CVE-2017-11534: A memory leak in the lite_font_map() in coders/wmf.c was fixed. (bsc#1050135)
* CVE-2017-13133: A memory exhaustion in load_level function in coders/xcf.c was fixed. (bsc#1055219)
* CVE-2017-13139: A out-of-bounds read in the ReadOneMNGImage was fixed. (bsc#1055430)

This update also reverts an incorrect fix for CVE-2016-7530 [bsc#1054924].");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.12.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.12.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.12.1", rls:"SLES12.0SP3"))) {
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
