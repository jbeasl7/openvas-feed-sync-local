# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0353");
  script_cve_id("CVE-2024-45508", "CVE-2024-46478");
  script_tag(name:"creation_date", value:"2024-11-11 04:11:21 +0000 (Mon, 11 Nov 2024)");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 16:44:08 +0000 (Wed, 04 Sep 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0353)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0353");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0353.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33737");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/RNU4P4P7ZCF5TYOAPMGGBX2KSE6IHZFT/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'htmldoc' package(s) announced via the MGASA-2024-0353 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTMLDOC before 1.9.19 has an out-of-bounds write in parse_paragraph in
ps-pdf.cxx because of an attempt to strip leading whitespace from a
whitespace-only node. (CVE-2024-45508)
HTMLDOC v1.9.18 contains a buffer overflow in parse_pre
function,ps-pdf.cxx:5681. (CVE-2024-46478)");

  script_tag(name:"affected", value:"'htmldoc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"htmldoc", rpm:"htmldoc~1.9.15~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"htmldoc-nogui", rpm:"htmldoc-nogui~1.9.15~3.1.mga9", rls:"MAGEIA9"))) {
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
