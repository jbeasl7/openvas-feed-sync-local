# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2778.1");
  script_cve_id("CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437", "CVE-2018-16323", "CVE-2018-16329");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 16:15:03 +0000 (Thu, 25 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2778-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2778-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182778-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106858");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004574.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:2778-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

The following security vulnerabilities were fixed:

- CVE-2018-16329: Prevent NULL pointer dereference in the GetMagickProperty
 function leading to DoS (bsc#1106858)
- CVE-2018-16323: ReadXBMImage left data uninitialized when processing an XBM
 file that has a negative pixel value. If the affected code was used as a
 library loaded into a process that includes sensitive information, that
 information sometimes can be leaked via the image data (bsc#1106855)
- CVE-2018-14434: Fixed a memory leak for a colormap in WriteMPCImage
 (bsc#1102003)
- CVE-2018-14435: Fixed a memory leak in DecodeImage in coders/pcd.c
 (bsc#1102007)
- CVE-2018-14436: Fixed a memory leak in ReadMIFFImage in coders/miff.c
 (bsc#1102005)
- CVE-2018-14437: Fixed a memory leak in parse8BIM in coders/meta.c
 (bsc#1102004)
- Disable PS, PS2, PS3, XPS and PDF coders in default policy.xml (bsc#1105592)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.74.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.74.1", rls:"SLES12.0SP3"))) {
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
