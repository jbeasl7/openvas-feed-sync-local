# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0055.1");
  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-11449", "CVE-2017-11751", "CVE-2017-12430", "CVE-2017-12642", "CVE-2017-14249", "CVE-2017-17680", "CVE-2017-17882", "CVE-2017-9409");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-08 14:04:03 +0000 (Tue, 08 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0055-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180055-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074610");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003582.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes several issues.

These security issues were fixed:

- CVE-2017-1000476: A CPU exhaustion vulnerability was found in the function
 ReadDDSInfo in coders/dds.c, which allowed attackers to cause a denial of
 service (bsc#1074610).
- CVE-2017-9409: The ReadMPCImage function in mpc.c allowed attackers to cause
 a denial of service (memory leak) via a crafted file (bsc#1042948).
- CVE-2017-1000445: A NULL pointer dereference in the MagickCore component
 might have lead to denial of service (bsc#1074425).
- CVE-2017-17680: Prevent a memory leak in the function ReadXPMImage in
 coders/xpm.c, which allowed attackers to cause a denial of service via a
 crafted XPM image file (a different vulnerability than CVE-2017-17882)
 (bsc#1072902).
- CVE-2017-17882: Prevent a memory leak in the function ReadXPMImage in
 coders/xpm.c, which allowed attackers to cause a denial of service via a
 crafted XPM image file (a different vulnerability than CVE-2017-17680)
 (bsc#1074122).
- CVE-2017-11449: coders/mpc did not enable seekable streams and thus could not
 validate blob sizes, which allowed remote attackers to cause a denial of
 service (application crash) or possibly have unspecified other impact via an
 image received from stdin (bsc#1049373).
- CVE-2017-12430: A memory exhaustion in the function ReadMPCImage in
 coders/mpc.c allowed attackers to cause DoS (bsc#1052252).
- CVE-2017-12642: Prevent a memory leak vulnerability in ReadMPCImage in
 coders\mpc.c via crafted file allowing for DoS (bsc#1052771).
- CVE-2017-14249: A mishandled EOF check in ReadMPCImage in coders/mpc.c that
 lead to a division by zero in GetPixelCacheTileSize in MagickCore/cache.c
 allowed remote attackers to cause a denial of service via a crafted file
 (bsc#1058082).
- Prevent memory leak via crafted file in pwp.c allowing for DoS (bsc#1051412)");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.23.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.23.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.23.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.23.1", rls:"SLES12.0SP3"))) {
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
