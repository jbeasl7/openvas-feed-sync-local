# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0149");
  script_cve_id("CVE-2022-1271");
  script_tag(name:"creation_date", value:"2022-04-25 04:24:37 +0000 (Mon, 25 Apr 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 16:42:33 +0000 (Wed, 07 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0149)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0149");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0149.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30261");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5378-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5378-2");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2976");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2977");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5122");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5123");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/04/08/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gzip, xz' package(s) announced via the MGASA-2022-0149 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zgrep, xzgrep: arbitrary-file-write vulnerability. (CVE-2022-1271)");

  script_tag(name:"affected", value:"'gzip, xz' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"gzip", rpm:"gzip~1.10~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lzma-devel", rpm:"lib64lzma-devel~5.2.5~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lzma5", rpm:"lib64lzma5~5.2.5~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma-devel", rpm:"liblzma-devel~5.2.5~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzma5", rpm:"liblzma5~5.2.5~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xz", rpm:"xz~5.2.5~2.1.mga8", rls:"MAGEIA8"))) {
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
