# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03150.1");
  script_cve_id("CVE-2025-55005", "CVE-2025-55154", "CVE-2025-55160", "CVE-2025-55212", "CVE-2025-55298", "CVE-2025-57803");
  script_tag(name:"creation_date", value:"2025-09-12 04:12:29 +0000 (Fri, 12 Sep 2025)");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 19:25:21 +0000 (Fri, 15 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03150-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03150-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503150-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248784");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041608.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2025:03150-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2025-55005: Fixed heap buffer overflow when transforming from Log to sRGB colorspaces (bsc#1248077).
- CVE-2025-55154: Fixed integer overflow when performing magnified size calculations in ReadOneMNGIMage (bsc#1248078).
- CVE-2025-55160: Fixed undefined behavior due to function-type-mismatch in CloneSplayTree (bsc#1248079).
- CVE-2025-55212: Fixed division-by-zero in ThumbnailImage() when passing a geometry string containing only a colon to
 `montage -geometry` (bsc#1248767).
- CVE-2025-55298: Fixed heap overflow due to format string bug vulnerability (bsc#1248780).
- CVE-2025-57803: Fixed heap out-of-bounds (OOB) write due to 32-bit integer overflow (bsc#1248784).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.212.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.212.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.8.8.1~71.212.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.8.8.1~71.212.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.212.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.212.1", rls:"SLES12.0SP5"))) {
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
