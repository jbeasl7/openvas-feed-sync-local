# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0224");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2016-0224)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0224");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0224.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18677");
  script_xref(name:"URL", value:"https://docs.google.com/document/d/1uxETuTL7_tVgE8EB49RhxxHuCyDIbcsS9fHNimBixm4/edit");
  script_xref(name:"URL", value:"https://wiki.mozilla.org/images/7/77/Libjpeg-turbo-report.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg' package(s) announced via the MGASA-2016-0224 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libjpeg packages fix security vulnerability:

Out-of-Bounds Read in libjpeg-turbo before 1.5.0 via unusually long
Blocks in MCU (LJT-01-005).");

  script_tag(name:"affected", value:"'libjpeg' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"jpeg-progs", rpm:"jpeg-progs~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg-devel", rpm:"lib64jpeg-devel~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg-static-devel", rpm:"lib64jpeg-static-devel~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg62", rpm:"lib64jpeg62~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg8", rpm:"lib64jpeg8~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64turbojpeg0", rpm:"lib64turbojpeg0~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg", rpm:"libjpeg~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-devel", rpm:"libjpeg-devel~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-static-devel", rpm:"libjpeg-static-devel~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62", rpm:"libjpeg62~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8", rpm:"libjpeg8~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0", rpm:"libturbojpeg0~1.3.1~4.1.mga5", rls:"MAGEIA5"))) {
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
