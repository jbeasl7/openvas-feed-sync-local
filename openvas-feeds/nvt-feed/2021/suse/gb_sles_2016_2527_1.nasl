# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2527.1");
  script_cve_id("CVE-2016-3186", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-5314", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5875");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 16:56:16 +0000 (Thu, 05 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2527-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2527-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162527-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987351");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002331.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2016:2527-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

- CVE-2016-3622: Specially crafted TIFF images could trigger a crash in tiff2rgba (bsc#974449)
- Various out-of-bound write vulnerabilities with unspecified impact (MSVR 35093, MSVR 35094, MSVR 35095, MSVR 35096, MSVR 35097, MSVR 35098)
- CVE-2016-5314: Specially crafted TIFF images could trigger a crash that could result in DoS (bsc#984831)
- CVE-2016-5316: Specially crafted TIFF images could trigger a crash in the rgb2ycbcr tool, leading to Doa (bsc#984837)
- CVE-2016-5317: Specially crafted TIFF images could trigger a crash through an out of bound write (bsc#984842)
- CVE-2016-5320: Specially crafted TIFF images could trigger a crash or potentially allow remote code execution when using the rgb2ycbcr command (bsc#984808)
- CVE-2016-5875: Specially crafted TIFF images could trigger could allow arbitrary code execution (bsc#987351)
- CVE-2016-3623: Specially crafted TIFF images could trigger a crash in rgb2ycbcr (bsc#974618)
- CVE-2016-3945: Specially crafted TIFF images could trigger a crash or allow for arbitrary command execution via tiff2rgba (bsc#974614)
- CVE-2016-3990: Specially crafted TIFF images could trigger a crash or allow for arbitrary command execution (bsc#975069)
- CVE-2016-3186: Specially crafted TIFF imaged could trigger a crash in the gif2tiff command via a buffer overflow (bsc#973340)");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~141.168.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff3-32bit", rpm:"libtiff3-32bit~3.8.2~141.168.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff3-x86", rpm:"libtiff3-x86~3.8.2~141.168.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~3.8.2~141.168.1", rls:"SLES11.0SP4"))) {
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
