# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0049");
  script_cve_id("CVE-2023-46303", "CVE-2024-6781", "CVE-2024-6782", "CVE-2024-7008", "CVE-2024-7009");
  script_tag(name:"creation_date", value:"2025-02-13 04:08:38 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-19 17:15:34 +0000 (Mon, 19 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0049)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0049");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0049.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33535");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PTG4W7NKCI3YSS24S3XTWQKFDUAR6BN3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'calibre' package(s) announced via the MGASA-2025-0049 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"link_to_local_path in ebooks/conversion/plugins/html_input.py in calibre
before 6.19.0 can, by default, add resources outside of the document
root. (CVE-2023-46303)
Path traversal in Calibre <= 7.14.0 allow unauthenticated attackers to
achieve arbitrary file read. (CVE-2024-6781)
Improper access control in Calibre 6.9.0 ~ 7.14.0 allow unauthenticated
attackers to achieve remote code execution. (CVE-2024-6782)
Unsanitized user-input in Calibre <= 7.15.0 allow attackers to perform
reflected cross-site scripting. (CVE-2024-7008)
Unsanitized user-input in Calibre <= 7.15.0 allow users with permissions
to perform full-text searches to achieve SQL injection on the SQLite
database. (CVE-2024-7009)");

  script_tag(name:"affected", value:"'calibre' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"calibre", rpm:"calibre~6.17.0~1.1.mga9", rls:"MAGEIA9"))) {
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
