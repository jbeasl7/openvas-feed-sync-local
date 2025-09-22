# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1712.1");
  script_cve_id("CVE-2017-12805", "CVE-2017-12806", "CVE-2019-10131", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11505", "CVE-2019-11506", "CVE-2019-11597", "CVE-2019-11598");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-27 00:32:48 +0000 (Sat, 27 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1712-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1712-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191712-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138464");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005633.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2019:1712-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

Security issues fixed:

- CVE-2019-11597: Fixed a heap-based buffer over-read in the WriteTIFFImage() (bsc#1138464).
- Fixed a file content disclosure via SVG and WMF decoding (bsc#1138425).- CVE-2019-11472: Fixed a denial of service in ReadXWDImage() (bsc#1133204).
- CVE-2019-11470: Fixed a denial of service in ReadCINImage() (bsc#1133205).
- CVE-2019-11506: Fixed a heap-based buffer overflow in the WriteMATLABImage() (bsc#1133498).
- CVE-2019-11505: Fixed a heap-based buffer overflow in the WritePDBImage() (bsc#1133501).
- CVE-2019-10131: Fixed a off-by-one read in formatIPTCfromBuffer function in coders/meta.c (bsc#1134075).
- CVE-2017-12806: Fixed a denial of service through memory exhaustion in format8BIM() (bsc#1135232).
- CVE-2017-12805: Fixed a denial of service through memory exhaustion in ReadTIFFImage() (bsc#1135236).
- CVE-2019-11598: Fixed a heap-based buffer over-read in WritePNMImage() (bsc#1136732)

We also now disable PCL in the -SUSE configuration, as it also uses ghostscript for decoding (bsc#1136183)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.123.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.123.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.123.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.123.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.123.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.123.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.123.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.123.2", rls:"SLES12.0SP4"))) {
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
