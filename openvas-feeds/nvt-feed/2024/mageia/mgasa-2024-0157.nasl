# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0157");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460");
  script_tag(name:"creation_date", value:"2024-05-01 04:12:41 +0000 (Wed, 01 May 2024)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:58:52 +0000 (Tue, 04 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0157)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0157");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0157.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33129");
  script_xref(name:"URL", value:"https://lwn.net/Articles/970778/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2024-0157 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This release is a security release and addresses multiple issues:
[Low] OutOfBound Read in zgfx_decompress_segment.
[Moderate] Integer overflow & OutOfBound Write in
clear_decompress_residual_data.
[Low] integer underflow in nsc_rle_decode.
[Low] OutOfBound Read in planar_skip_plane_rle.
[Low] OutOfBound Read in ncrush_decompress.
[Low] OutOfBound Read in interleaved_decompress.");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.11.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.11.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.11.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.11.7~1.mga9", rls:"MAGEIA9"))) {
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
