# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0157.1");
  script_cve_id("CVE-2021-28021", "CVE-2021-42715", "CVE-2021-42716");
  script_tag(name:"creation_date", value:"2022-01-25 03:26:30 +0000 (Tue, 25 Jan 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-20 20:31:23 +0000 (Wed, 20 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0157-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220157-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zxing-cpp' package(s) announced via the SUSE-SU-2022:0157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zxing-cpp fixes the following issues:

CVE-2021-28021: Fixed buffer overflow vulnerability in function
 stbi__extend_receive in stb_image.h via a crafted JPEG file.
 (bsc#1191743).

CVE-2021-42715: Fixed buffer overflow in stb_image PNM loader
 (bsc#1191942).

CVE-2021-42716: Fixed denial of service in stb_image HDR loader when
 reading crafted HDR files (bsc#1191944).");

  script_tag(name:"affected", value:"'zxing-cpp' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libZXing1", rpm:"libZXing1~1.2.0~9.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libZXing1-debuginfo", rpm:"libZXing1-debuginfo~1.2.0~9.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zxing-cpp-debugsource", rpm:"zxing-cpp-debugsource~1.2.0~9.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zxing-cpp-devel", rpm:"zxing-cpp-devel~1.2.0~9.7.1", rls:"SLES15.0SP3"))) {
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
