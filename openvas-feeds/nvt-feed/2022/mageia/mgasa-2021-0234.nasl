# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0234");
  script_cve_id("CVE-2021-25900");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 19:56:31 +0000 (Tue, 02 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0234)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0234");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0234.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29055");
  script_xref(name:"URL", value:"https://github.com/servo/rust-smallvec/commit/5757ac500d4e544485d796b542e4e589749c291b");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librsvg' package(s) announced via the MGASA-2021-0234 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update patches the vendored `smallvec` Rust create in librsvg to fix a security vulnerability:

The Iterator implementation mishandles destructors, leading to a double free (CVE-2021-25900).");

  script_tag(name:"affected", value:"'librsvg' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64rsvg-gir2.0", rpm:"lib64rsvg-gir2.0~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rsvg2-devel", rpm:"lib64rsvg2-devel~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rsvg2_2", rpm:"lib64rsvg2_2~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg", rpm:"librsvg~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-gir2.0", rpm:"librsvg-gir2.0~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg2-devel", rpm:"librsvg2-devel~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg2_2", rpm:"librsvg2_2~2.45.5~3.2.mga7", rls:"MAGEIA7"))) {
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
