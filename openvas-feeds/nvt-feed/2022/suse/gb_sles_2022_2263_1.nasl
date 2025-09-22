# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2263.1");
  script_cve_id("CVE-2019-17540", "CVE-2022-32545", "CVE-2022-32546", "CVE-2022-32547");
  script_tag(name:"creation_date", value:"2022-07-06 04:40:49 +0000 (Wed, 06 Jul 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 18:14:45 +0000 (Thu, 30 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2263-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2263-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222263-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200389");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-July/011398.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2022:2263-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

 - CVE-2019-17540: Fixed heap-based buffer overflow in ReadPSInfo in coders/ps.c. (bsc#1153866)
 - CVE-2022-32545: Fixed an outside the range of representable values of type. (bsc#1200388)
 - CVE-2022-32546: Fixed an outside the range of representable values of type. (bsc#1200389)
 - CVE-2022-32547: Fixed a load of misaligned address at MagickCore/property.c. (bsc#1200387)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.177.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.177.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.177.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.177.1", rls:"SLES12.0SP5"))) {
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
