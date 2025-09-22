# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131136");
  script_cve_id("CVE-2015-8126");
  script_tag(name:"creation_date", value:"2015-11-23 05:46:11 +0000 (Mon, 23 Nov 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0451)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0451");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0451.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/11/13/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17161");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng, libpng12' package(s) announced via the MGASA-2015-0451 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple buffer overflows in the png_set_PLTE and png_get_PLTE functions
in libpng before 1.6.19 allow remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact via
a small bit-depth value in an IHDR (aka image header) chunk in a PNG image
(CVE-2015-8126).

This issue also affected libpng 1.2 before 1.2.54. The libpng and
libpng12 packages have been updated to versions 1.6.19 and 1.2.54,
respectively, fixing this issue.");

  script_tag(name:"affected", value:"'libpng, libpng12' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.6.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png12-devel", rpm:"lib64png12-devel~1.2.54~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png12_0", rpm:"lib64png12_0~1.2.54~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png16_16", rpm:"lib64png16_16~1.6.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.6.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12", rpm:"libpng12~1.2.54~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-devel", rpm:"libpng12-devel~1.2.54~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12_0", rpm:"libpng12_0~1.2.54~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16_16", rpm:"libpng16_16~1.6.19~1.mga5", rls:"MAGEIA5"))) {
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
