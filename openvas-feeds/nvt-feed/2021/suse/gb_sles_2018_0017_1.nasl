# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0017.1");
  script_cve_id("CVE-2017-12563", "CVE-2017-12691", "CVE-2017-13061", "CVE-2017-13062", "CVE-2017-14042", "CVE-2017-14174", "CVE-2017-14343", "CVE-2017-15277", "CVE-2017-15281");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-19 21:12:48 +0000 (Thu, 19 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0017-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180017-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063050");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003569.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- security update (xcf.c):
 * CVE-2017-14343: Memory leak vulnerability in ReadXCFImage could lead to denial of service via a crafted file.
 CVE-2017-12691: The ReadOneLayer function in coders/xcf.c allows remote attackers to cause a denial of service
 (memory consumption) via a crafted file.
 [bsc#1058422]

- security update (pnm.c):
 * CVE-2017-14042: A memory allocation failure was discovered in the ReadPNMImage function in coders/pnm.c and
 could lead to remote denial of service [bsc#1056550]

- security update (psd.c):
 * CVE-2017-15281: ReadPSDImage allows remote attackers to cause a denial of service (application crash) or
 possibly have unspecified other impact via a crafted file [bsc#1063049]
 * CVE-2017-13061: A length-validation vulnerability was found in the function ReadPSDLayersInternal in coders/psd.c,
 which allows attackers to cause a denial of service (ReadPSDImage memory exhaustion) via a crafted file. [bsc#1055063]
 * CVE-2017-12563: A Memory exhaustion vulnerability was found in the function ReadPSDImage in coders/psd.c,
 which allows attackers to cause a denial of service. [bsc#1052460]
 * CVE-2017-14174: Due to a lack of an EOF check (End of File) in ReadPSDLayersInternal could cause huge CPU consumption,
 when a crafted PSD file, which claims a large 'length' field in the header but does not contain sufficient backing data,
 is provided, the loop over \'length\' would consume huge CPU resources, since there is no EOF check inside the loop.[bsc#1057723]

- security update (meta.c):
 * CVE-2017-13062: Amemory leak vulnerability was found in the function formatIPTC in coders/meta.c,
 which allows attackers to cause a denial of service (WriteMETAImage memory consumption) via a crafted file [bsc#1055053]

- security update (gif.c):
 * CVE-2017-15277: ReadGIFImage in coders/gif.c leaves the palette uninitialized when processing a GIF file that has neither
 a global nor local palette. If the affected product is used as a library loaded into a process that operates on interesting
 data, this data sometimes can be leaked via the uninitialized palette.[bsc#1063050]");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.20.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.20.1", rls:"SLES12.0SP3"))) {
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
