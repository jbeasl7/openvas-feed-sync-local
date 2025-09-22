# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2010.1");
  script_cve_id("CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13133", "CVE-2019-13134", "CVE-2019-13135", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13307", "CVE-2019-13308", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13391", "CVE-2019-13454");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-08 17:22:11 +0000 (Mon, 08 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2010-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192010-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141171");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2019:2010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2019-13301: Fixed a memory leak in AcquireMagickMemory() (bsc#1140554).
- CVE-2019-13310: Fixed a memory leak at AcquireMagickMemory because of an error in MagickWand/mogrify.c (bsc#1140501).
- CVE-2019-13311: Fixed a memory leak at AcquireMagickMemory because of a wand/mogrify.c error (bsc#1140513).
- CVE-2019-13454: Fixed a division by zero in RemoveDuplicateLayers in MagickCore/layer.c (bsc#1141171).
- CVE-2019-13295: Fixed a heap-based buffer over-read at MagickCore/threshold.c in AdaptiveThresholdImage (bsc#1140664).
- CVE-2019-13297: Fixed a heap-based buffer over-read at MagickCore/threshold.c in AdaptiveThresholdImage (bsc#1140666).
- CVE-2019-12979: Fixed the use of uninitialized values in SyncImageSettings() (bsc#1139886).
- CVE-2019-13391: Fixed a heap-based buffer over-read in MagickCore/fourier.c (bsc#1140673).
- CVE-2019-13308: Fixed a heap-based buffer overflow in MagickCore/fourier.c (bsc#1140534).
- CVE-2019-13300: Fixed a heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages (bsc#1140669).
- CVE-2019-13307: Fixed a heap-based buffer overflow at MagickCore/statistic.c (bsc#1140538).
- CVE-2019-12975: Fixed a memory leak in the WriteDPXImage() in coders/dpx.c (bsc#1140106).
- CVE-2019-13135: Fixed the use of uninitialized values in ReadCUTImage() (bsc#1140103).
- CVE-2019-12978: Fixed the use of uninitialized values in ReadPANGOImage() (bsc#1139885).
- CVE-2019-12974: Fixed a NULL pointer dereference in the ReadPANGOImage() (bsc#1140111).
- CVE-2019-13133: Fixed a memory leak in the ReadBMPImage() (bsc#1140100).
- CVE-2019-13134: Fixed a memory leak in the ReadVIFFImage() (bsc#1140102).
- CVE-2019-12976: Fixed a memory leak in the ReadPCLImage() in coders/pcl.c(bsc#1140110).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.126.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.126.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.126.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.126.1", rls:"SLES12.0SP4"))) {
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
