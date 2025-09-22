# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1140.1");
  script_cve_id("CVE-2016-10219", "CVE-2016-9601", "CVE-2017-11714", "CVE-2017-7207", "CVE-2017-9216", "CVE-2017-9612", "CVE-2017-9726", "CVE-2017-9727", "CVE-2017-9739", "CVE-2017-9835");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-07 15:13:52 +0000 (Mon, 07 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1140-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181140-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051184");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/003973.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript-library' package(s) announced via the SUSE-SU-2018:1140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript-library fixes several issues.

These security issues were fixed:

- CVE-2017-7207: The mem_get_bits_rectangle function allowed remote attackers
 to cause a denial of service (NULL pointer dereference) via a crafted
 PostScript document (bsc#1030263).
- CVE-2016-9601: Prevent heap-buffer overflow by checking for an integer
 overflow in jbig2_image_new function (bsc#1018128).
- CVE-2017-9612: The Ins_IP function in base/ttinterp.c allowed remote
 attackers to cause a denial of service (use-after-free and application crash)
 or possibly have unspecified other impact via a crafted document (bsc#1050891)
- CVE-2017-9726: The Ins_MDRP function in base/ttinterp.c allowed remote
 attackers to cause a denial of service (heap-based buffer over-read and
 application crash) or possibly have unspecified other impact via a crafted
 document (bsc#1050889)
- CVE-2017-9727: The gx_ttfReader__Read function in base/gxttfb.c allowed
 remote attackers to cause a denial of service (heap-based buffer over-read and
 application crash) or possibly have unspecified other impact via a crafted
 document (bsc#1050888)
- CVE-2017-9739: The Ins_JMPR function in base/ttinterp.c allowed remote
 attackers to cause a denial of service (heap-based buffer over-read and
 application crash) or possibly have unspecified other impact via a crafted
 document (bsc#1050887)
- CVE-2017-11714: psi/ztoken.c mishandled references to the scanner state
 structure, which allowed remote attackers to cause a denial of service
 (application crash) or possibly have unspecified other impact via a crafted
 PostScript document, related to an out-of-bounds read in the
 igc_reloc_struct_ptr function in psi/igc.c (bsc#1051184)
- CVE-2017-9835: The gs_alloc_ref_array function allowed remote attackers to
 cause a denial of service (heap-based buffer overflow and application crash) or
 possibly have unspecified other impact via a crafted PostScript document
 (bsc#1050879)
- CVE-2016-10219: The intersect function in base/gxfill.c allowed remote
 attackers to cause a denial of service (divide-by-zero error and application
 crash) via a crafted file (bsc#1032138)
- CVE-2017-9216: Prevent NULL pointer dereference in the jbig2_huffman_get
 function in jbig2_huffman.c which allowed for DoS (bsc#1040643)");

  script_tag(name:"affected", value:"'ghostscript-library' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-other", rpm:"ghostscript-fonts-other~8.62~32.47.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-rus", rpm:"ghostscript-fonts-rus~8.62~32.47.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-fonts-std", rpm:"ghostscript-fonts-std~8.62~32.47.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-library", rpm:"ghostscript-library~8.62~32.47.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-omni", rpm:"ghostscript-omni~8.62~32.47.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~8.62~32.47.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpprint", rpm:"libgimpprint~4.2.7~32.47.7.1", rls:"SLES11.0SP4"))) {
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
