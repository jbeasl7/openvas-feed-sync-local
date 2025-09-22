# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0221");
  script_cve_id("CVE-2024-5197");
  script_tag(name:"creation_date", value:"2024-06-17 04:12:21 +0000 (Mon, 17 Jun 2024)");
  script_version("2025-07-23T05:44:57+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:57 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-22 18:17:56 +0000 (Tue, 22 Jul 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0221");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0221.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33281");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6814-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvpx' package(s) announced via the MGASA-2024-0221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There exists integer overflows in libvpx in versions prior to 1.14.1.
Calling vpx_img_alloc() with a large value of the d_w, d_h, or align
parameter may result in integer overflows in the calculations of buffer
sizes and offsets and some fields of the returned vpx_image_t struct may
be invalid. Calling vpx_img_wrap() with a large value of the d_w, d_h,
or stride_align parameter may result in integer overflows in the
calculations of buffer sizes and offsets and some fields of the returned
vpx_image_t struct may be invalid. (CVE-2024-5197)");

  script_tag(name:"affected", value:"'libvpx' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vpx-devel", rpm:"lib64vpx-devel~1.12.0~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vpx7", rpm:"lib64vpx7~1.12.0~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx", rpm:"libvpx~1.12.0~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.12.0~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-utils", rpm:"libvpx-utils~1.12.0~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx7", rpm:"libvpx7~1.12.0~1.3.mga9", rls:"MAGEIA9"))) {
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
