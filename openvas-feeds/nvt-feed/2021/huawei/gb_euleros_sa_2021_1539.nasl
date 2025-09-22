# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1539");
  script_cve_id("CVE-2020-14373", "CVE-2020-16287", "CVE-2020-16288", "CVE-2020-16289", "CVE-2020-16290", "CVE-2020-16291", "CVE-2020-16292", "CVE-2020-16293", "CVE-2020-16294", "CVE-2020-16295", "CVE-2020-16296", "CVE-2020-16297", "CVE-2020-16298", "CVE-2020-16299", "CVE-2020-16300", "CVE-2020-16301", "CVE-2020-16302", "CVE-2020-16303", "CVE-2020-16304", "CVE-2020-16305", "CVE-2020-16306", "CVE-2020-16307", "CVE-2020-16308", "CVE-2020-16309", "CVE-2020-16310", "CVE-2020-17538");
  script_tag(name:"creation_date", value:"2021-03-05 07:09:51 +0000 (Fri, 05 Mar 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:01:14 +0000 (Fri, 14 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2021-1539)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1539");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1539");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2021-1539 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability in jetp3852_print_page() in devices/gdev3852.c of Artifex Software GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted PDF file. This is fixed in v9.51.(CVE-2020-16302)

A use-after-free vulnerability in xps_finish_image_path() in devices/vector/gdevxps.c of Artifex Software GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted PDF file. This is fixed in v9.51.(CVE-2020-16303)

A use after free was found in igc_reloc_struct_ptr() of psi/igc.c of ghostscript-9.25. A local attacker could supply a specially crafted PDF file to cause a denial of service.(CVE-2020-14373)

A buffer overflow vulnerability in GetNumSameData() in contrib/lips4/gdevlips.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.(CVE-2020-17538)

A division by zero vulnerability in dot24_print_page() in devices/gdevdm24.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.(CVE-2020-16310)

A buffer overflow vulnerability in lxm5700m_print_page() in devices/gdevlxm.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted eps file. This is fixed in v9.51.(CVE-2020-16309)

A buffer overflow vulnerability in p_print_image() in devices/gdevcdj.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.(CVE-2020-16308)

A null pointer dereference vulnerability in devices/vector/gdevtxtw.c and psi/zbfont.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted postscript file. This is fixed in v9.51.(CVE-2020-16307)

A null pointer dereference vulnerability in devices/gdevtsep.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted postscript file. This is fixed in v9.51.(CVE-2020-16306)

A buffer overflow vulnerability in pcx_write_rle() in contrib/japanese/gdev10v.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.(CVE-2020-16305)

A buffer overflow vulnerability in image_render_color_thresh() in base/gxicolor.c of Artifex Software GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted eps file. This is fixed in v9.51.(CVE-2020-16304)

A buffer overflow vulnerability in okiibm_print_page1() in devices/gdevokii.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.(CVE-2020-16301)

A buffer overflow vulnerability in tiff12_print_page() in devices/gdevtfnx.c of Artifex Software GhostScript v9.50 allows a remote attacker to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.25~1.h10.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs", rpm:"libgs~9.25~1.h10.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
