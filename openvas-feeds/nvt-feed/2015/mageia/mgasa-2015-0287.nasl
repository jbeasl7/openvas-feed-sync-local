# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130091");
  script_cve_id("CVE-2015-1270");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:36 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0287)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0287");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0287.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.cz/2015/07/stable-channel-update_21.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16478");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the MGASA-2015-0287 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ucnv_io_getConverterName function in common/ucnv_io.cpp in
International Components for Unicode (ICU) mishandles converter names with
initial x- substrings, which allows remote attackers to cause a denial of
service (read of uninitialized memory) or possibly have unspecified other
impact via a crafted file (CVE-2015-1270).");

  script_tag(name:"affected", value:"'icu' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"icu", rpm:"icu~53.1~12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu-doc", rpm:"icu-doc~53.1~12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu53-data", rpm:"icu53-data~53.1~12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64icu-devel", rpm:"lib64icu-devel~53.1~12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64icu53", rpm:"lib64icu53~53.1~12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-devel", rpm:"libicu-devel~53.1~12.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu53", rpm:"libicu53~53.1~12.1.mga5", rls:"MAGEIA5"))) {
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
