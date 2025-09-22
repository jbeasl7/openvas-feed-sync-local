# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1844.1");
  script_cve_id("CVE-2022-25308", "CVE-2022-25309", "CVE-2022-25310");
  script_tag(name:"creation_date", value:"2022-05-26 04:26:34 +0000 (Thu, 26 May 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 14:49:57 +0000 (Thu, 08 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1844-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1844-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221844-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fribidi' package(s) announced via the SUSE-SU-2022:1844-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fribidi fixes the following issues:

CVE-2022-25308: Fixed stack out of bounds read (bsc#1196147).

CVE-2022-25309: Fixed heap-buffer-overflow in fribidi_cap_rtl_to_unicode
 (bsc#1196148).

CVE-2022-25310: Fixed NULL pointer dereference in
 fribidi_remove_bidi_marks (bsc#1196150).");

  script_tag(name:"affected", value:"'fribidi' package(s) on SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"fribidi", rpm:"fribidi~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fribidi-debuginfo", rpm:"fribidi-debuginfo~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fribidi-debugsource", rpm:"fribidi-debugsource~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fribidi-devel", rpm:"fribidi-devel~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfribidi0", rpm:"libfribidi0~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfribidi0-debuginfo", rpm:"libfribidi0-debuginfo~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfribidi0-32bit", rpm:"libfribidi0-32bit~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfribidi0-32bit-debuginfo", rpm:"libfribidi0-32bit-debuginfo~1.0.5~150200.3.6.1", rls:"SLES15.0SP3"))) {
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
