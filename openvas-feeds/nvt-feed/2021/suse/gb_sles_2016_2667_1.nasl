# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2667.1");
  script_cve_id("CVE-2014-9907", "CVE-2015-8957", "CVE-2015-8958", "CVE-2015-8959", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7513", "CVE-2016-7514", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519", "CVE-2016-7520", "CVE-2016-7521", "CVE-2016-7522", "CVE-2016-7523", "CVE-2016-7524", "CVE-2016-7525", "CVE-2016-7526", "CVE-2016-7527", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7530", "CVE-2016-7531", "CVE-2016-7532", "CVE-2016-7533", "CVE-2016-7534", "CVE-2016-7535", "CVE-2016-7537", "CVE-2016-7538", "CVE-2016-7539", "CVE-2016-7540", "CVE-2016-7799", "CVE-2016-7800", "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8677", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 18:19:56 +0000 (Thu, 27 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2667-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2667-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162667-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005328");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002373.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2016:2667-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

These vulnerabilities could be triggered by processing specially crafted image files,
which could lead to a process crash or resource consumtion, or potentially have unspecified futher impact.

- CVE-2016-8684: Mismatch between real filesize and header values (bsc#1005123)
- CVE-2016-8683: Check that filesize is reasonable compared to the header value (bsc#1005127)
- CVE-2016-8682: Stack-buffer read overflow while reading SCT header (bsc#1005125)
- CVE-2016-8677: Memory allocation failure in AcquireQuantumPixels (bsc#1005328)
- CVE-2016-7996, CVE-2016-7997: WPG Reader Issues (bsc#1003629)
- CVE-2016-7800: 8BIM/8BIMW unsigned underflow leads to heap overflow (bsc#1002422)
- CVE-2016-7799: mogrify global buffer overflow (bsc#1002421)
- CVE-2016-7540: writing to RGF format aborts (bsc#1000394)
- CVE-2016-7539: Potential DOS by not releasing memory (bsc#1000715)
- CVE-2016-7538: SIGABRT for corrupted pdb file (bsc#1000712)
- CVE-2016-7537: Out of bound access for corrupted pdb file (bsc#1000711)
- CVE-2016-7535: Out of bound access for corrupted psd file (bsc#1000709)
- CVE-2016-7534: Out of bound access in generic decoder (bsc#1000708)
- CVE-2016-7533: Wpg file out of bound for corrupted file (bsc#1000707)
- CVE-2016-7532: fix handling of corrupted psd file (bsc#1000706)
- CVE-2016-7531: Pbd file out of bound access (bsc#1000704)
- CVE-2016-7530: Out of bound in quantum handling (bsc#1000703)
- CVE-2016-7529: Out-of-bound in quantum handling (bsc#1000399)
- CVE-2016-7528: Out-of-bound access in xcf file coder (bsc#1000434)
- CVE-2016-7527: Out-of-bound access in wpg file coder: (bsc#1000436)
- CVE-2016-7526: out-of-bounds write in ./MagickCore/pixel-accessor.h (bsc#1000702)
- CVE-2016-7525: Heap buffer overflow in psd file coder (bsc#1000701)
- CVE-2016-7524: AddressSanitizer:heap-buffer-overflow READ of size 1 in meta.c:465 (bsc#1000700)
- CVE-2016-7523: AddressSanitizer:heap-buffer-overflow READ of size 1 meta.c:496 (bsc#1000699)
- CVE-2016-7522: Out of bound access for malformed psd file (bsc#1000698)
- CVE-2016-7521: Heap buffer overflow in psd file handling (bsc#1000697)
- CVE-2016-7520: Heap overflow in hdr file handling (bsc#1000696)
- CVE-2016-7519: Out-of-bounds read in coders/rle.c (bsc#1000695)
- CVE-2016-7518: Out-of-bounds read in coders/sun.c (bsc#1000694)
- CVE-2016-7517: Out-of-bounds read in coders/pict.c (bsc#1000693)
- CVE-2016-7516: Out-of-bounds problem in rle, pict, viff and sun files (bsc#1000692)
- CVE-2016-7515: Rle file handling for corrupted file (bsc#1000689)
- CVE-2016-7514: Out-of-bounds read in coders/psd.c (bsc#1000688)
- CVE-2016-7513: Off-by-one error leading to segfault (bsc#1000686)
- CVE-2016-7101: raphicsMagick: SGI Coder Out-Of-Bounds Read Vulnerability (bsc#1001221)
- CVE-2016-6823: raphicsMagick: BMP Coder Out-Of-Bounds Write Vulnerability (bsc#1001066)
- CVE-2015-8959: dOS due ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~40.1", rls:"SLES12.0SP1"))) {
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
