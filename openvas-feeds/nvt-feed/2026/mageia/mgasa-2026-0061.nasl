# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0061");
  script_cve_id("CVE-2026-32776", "CVE-2026-32777", "CVE-2026-32778");
  script_tag(name:"creation_date", value:"2026-03-23 04:49:35 +0000 (Mon, 23 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 15:52:53 +0000 (Tue, 17 Mar 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0061");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0061.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35227");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/17/10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the MGASA-2026-0061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libexpat before 2.7.5 allows a NULL pointer dereference with empty
external parameter entity content. (CVE-2026-32776)
libexpat before 2.7.5 allows an infinite loop while parsing DTD content.
(CVE-2026-32777)
libexpat before 2.7.5 allows a NULL pointer dereference in the function
setContext on retry after an earlier out-of-memory condition.
(CVE-2026-32778)");

  script_tag(name:"affected", value:"'expat' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.7.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat-devel", rpm:"lib64expat-devel~2.7.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat1", rpm:"lib64expat1~2.7.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.7.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.7.5~1.mga9", rls:"MAGEIA9"))) {
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
