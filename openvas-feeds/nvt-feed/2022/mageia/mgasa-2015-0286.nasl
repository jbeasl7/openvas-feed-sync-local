# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0286");
  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2015-1270");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0286");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0286.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.cz/2015/07/stable-channel-update_21.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16478");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/602540");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the MGASA-2015-0286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ICU Project's ICU4C library, before 55.1, contains a heap-based buffer
overflow in the resolveImplicitLevels function of ubidi.c (CVE-2014-8146).

The ICU Project's ICU4C library, before 55.1, contains an integer overflow
in the resolveImplicitLevels function of ubidi.c due to the assignment of
an int32 value to an int16 type (CVE-2014-8147).

The ucnv_io_getConverterName function in common/ucnv_io.cpp in
International Components for Unicode (ICU) mishandles converter names with
initial x- substrings, which allows remote attackers to cause a denial of
service (read of uninitialized memory) or possibly have unspecified other
impact via a crafted file (CVE-2015-1270).");

  script_tag(name:"affected", value:"'icu' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"icu", rpm:"icu~52.1~2.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu-data", rpm:"icu-data~52.1~2.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu-doc", rpm:"icu-doc~52.1~2.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64icu-devel", rpm:"lib64icu-devel~52.1~2.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64icu52", rpm:"lib64icu52~52.1~2.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-devel", rpm:"libicu-devel~52.1~2.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52", rpm:"libicu52~52.1~2.4.mga4", rls:"MAGEIA4"))) {
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
