# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0350.1");
  script_cve_id("CVE-2017-10995", "CVE-2017-11505", "CVE-2017-11525", "CVE-2017-11526", "CVE-2017-11539", "CVE-2017-11639", "CVE-2017-11750", "CVE-2017-12565", "CVE-2017-12640", "CVE-2017-12641", "CVE-2017-12643", "CVE-2017-12671", "CVE-2017-12673", "CVE-2017-12676", "CVE-2017-12935", "CVE-2017-13141", "CVE-2017-13142", "CVE-2017-13147", "CVE-2017-14103", "CVE-2017-14649", "CVE-2017-15218", "CVE-2017-17504", "CVE-2017-17879", "CVE-2017-17884", "CVE-2017-17914", "CVE-2017-18027", "CVE-2017-18029", "CVE-2017-9261", "CVE-2017-9262", "CVE-2018-5685");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-29 14:03:38 +0000 (Fri, 29 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0350-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180350-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076051");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003703.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0350-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes several issues.

These security issues were fixed:

- CVE-2018-5685: Prevent infinite loop and application hang in the ReadBMPImage
 function. Remote attackers could leverage this vulnerability to cause a denial
 of service via an image file with a crafted bit-field mask value (bsc#1075939)
- CVE-2017-11639: Prevent heap-based buffer over-read in the WriteCIPImage()
 function, related to the GetPixelLuma function in MagickCore/pixel-accessor.h
 (bsc#1050635).
- CVE-2017-11525: Prevent memory consumption in the ReadCINImage function that
 allowed remote attackers to cause a denial of service (bsc#1050098).
- CVE-2017-9262: The ReadJNGImage function in coders/png.c allowed attackers to
 cause a denial of service (memory leak) via a crafted file (bsc#1043353)
- CVE-2017-9261: The ReadMNGImage function in coders/png.c allowed
 attackers to cause a denial of service (memory leak) via a crafted file (bsc#1043354)
- CVE-2017-10995: The mng_get_long function in coders/png.c allowed remote
 attackers to cause a denial of service (heap-based buffer over-read and
 application crash) via a crafted MNG image (bsc#1047908)
- CVE-2017-11539: Prevent memory leak in the ReadOnePNGImage() function in
 coders/png.c (bsc#1050037)
- CVE-2017-11505: The ReadOneJNGImage function in coders/png.c allowed remote
 attackers to cause a denial of service (large loop and CPU consumption) via
 a crafted file (bsc#1050072)
- CVE-2017-11526: The ReadOneMNGImage function in coders/png.c allowed remote
 attackers to cause a denial of service (large loop and CPU consumption) via a
 crafted file (bsc#1050100)
- CVE-2017-11750: The ReadOneJNGImage function in coders/png.c allowed remote
 attackers to cause a denial of service (NULL pointer dereference) via a crafted
 file (bsc#1051442)
- CVE-2017-12565: Prevent memory leak in the function ReadOneJNGImage in
 coders/png.c, which allowed attackers to cause a denial of service (bsc#1052470)
- CVE-2017-12676: Prevent memory leak in the function ReadOneJNGImage in
 coders/png.c, which allowed attackers to cause a denial of service (bsc#1052708)
- CVE-2017-12673: Prevent memory leak in the function ReadOneMNGImage in
 coders/png.c, which allowed attackers to cause a denial of service (bsc#1052717)
- CVE-2017-12671: Added NULL assignment in coders/png.c to prevent an invalid
 free in the function RelinquishMagickMemory in MagickCore/memory.c, which
 allowed attackers to cause a denial of service (bsc#1052721)
- CVE-2017-12643: Prevent a memory exhaustion vulnerability in ReadOneJNGImage
 in coders\png.c (bsc#1052768)
- CVE-2017-12641: Prevent a memory leak vulnerability in ReadOneJNGImage in
 coders\png.c (bsc#1052777)
- CVE-2017-12640: Prevent an out-of-bounds read vulnerability in
 ReadOneMNGImage in coders/png.c (bsc#1052781)
- CVE-2017-12935: The ReadMNGImage function in coders/png.c mishandled large
 MNG images, leading to an ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~7.78.29.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~7.78.29.2", rls:"SLES11.0SP4"))) {
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
