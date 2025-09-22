# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130037");
  script_cve_id("CVE-2015-0851");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:51 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0350");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0350.html");
  script_xref(name:"URL", value:"http://shibboleth.net/community/advisories/secadv_20150721.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16514");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3321");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensaml, xmltooling' package(s) announced via the MGASA-2015-0350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xmltooling and opensaml packages fix security vulnerability:

The InCommon Shibboleth Training team discovered that XMLTooling, a C++ XML
parsing library, did not properly handle an exception when parsing well-formed
but schema-invalid XML. This could allow remote attackers to cause a denial of
service (crash) via crafted XML data (CVE-2015-0851).");

  script_tag(name:"affected", value:"'opensaml, xmltooling' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64opensaml-devel", rpm:"lib64opensaml-devel~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensaml8", rpm:"lib64opensaml8~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xmltooling-devel", rpm:"lib64xmltooling-devel~1.5.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xmltooling6", rpm:"lib64xmltooling6~1.5.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensaml-devel", rpm:"libopensaml-devel~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensaml8", rpm:"libopensaml8~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~1.5.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling6", rpm:"libxmltooling6~1.5.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensaml", rpm:"opensaml~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensaml-bin", rpm:"opensaml-bin~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensaml-schemas", rpm:"opensaml-schemas~2.5.2~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling", rpm:"xmltooling~1.5.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~1.5.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64opensaml-devel", rpm:"lib64opensaml-devel~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensaml8", rpm:"lib64opensaml8~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xmltooling-devel", rpm:"lib64xmltooling-devel~1.5.3~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xmltooling6", rpm:"lib64xmltooling6~1.5.3~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensaml-devel", rpm:"libopensaml-devel~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensaml8", rpm:"libopensaml8~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling-devel", rpm:"libxmltooling-devel~1.5.3~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmltooling6", rpm:"libxmltooling6~1.5.3~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensaml", rpm:"opensaml~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensaml-bin", rpm:"opensaml-bin~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensaml-schemas", rpm:"opensaml-schemas~2.5.2~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling", rpm:"xmltooling~1.5.3~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmltooling-schemas", rpm:"xmltooling-schemas~1.5.3~5.1.mga5", rls:"MAGEIA5"))) {
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
