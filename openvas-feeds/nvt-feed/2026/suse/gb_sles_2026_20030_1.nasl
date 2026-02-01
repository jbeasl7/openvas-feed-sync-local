# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20030.1");
  script_cve_id("CVE-2025-64505", "CVE-2025-64506", "CVE-2025-64720", "CVE-2025-65018", "CVE-2025-66293");
  script_tag(name:"creation_date", value:"2026-01-16 04:26:57 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20030-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20030-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620030-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254480");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023774.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng16' package(s) announced via the SUSE-SU-2026:20030-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libpng16 fixes the following issues:

- CVE-2025-64505: heap buffer over-read in `png_do_quantize` when processing PNG files malformed palette indices
 (bsc#1254157).
- CVE-2025-64506: heap buffer over-read in `png_write_image_8bit` when processing 8-bit input with `convert_to_8bit`
 enabled (bsc#1254158).
- CVE-2025-64720: out-of-bounds read in `png_image_read_composite` when processing palette images with
 `PNG_FLAG_OPTIMIZE_ALPHA` enabled (bsc#1254159).
- CVE-2025-65018: heap buffer overflow in `png_image_finish_read` when processing specially crafted 16-bit interlaced
 PNGs with 8-bit output format (bsc#1254160).
- CVE-2025-66293: out-of-bounds read of the `png_sRGB_base` array when processing palette PNG images with partial
 transparency and gamma correction (bsc#1254480).");

  script_tag(name:"affected", value:"'libpng16' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16", rpm:"libpng16-16~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-x86-64-v3", rpm:"libpng16-16-x86-64-v3~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel", rpm:"libpng16-compat-devel~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel-x86-64-v3", rpm:"libpng16-compat-devel-x86-64-v3~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel", rpm:"libpng16-devel~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel-x86-64-v3", rpm:"libpng16-devel-x86-64-v3~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-tools", rpm:"libpng16-tools~1.6.44~160000.3.1", rls:"SLES16.0.0"))) {
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
