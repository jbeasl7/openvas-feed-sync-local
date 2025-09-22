# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0067");
  script_cve_id("CVE-2019-10732");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-09 18:14:05 +0000 (Tue, 09 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2021-0067)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0067");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0067.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28260");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UIP7JD6E7AKTOSG2IAFVY4AE7G4NZIKB/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'messagelib' package(s) announced via the MGASA-2021-0067 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In KDE KMail, an attacker in possession of S/MIME or PGP encrypted emails can
wrap them as sub-parts within a crafted multipart email. The encrypted part(s)
can further be hidden using HTML/CSS or ASCII newline characters. This modified
multipart email can be re-sent by the attacker to the intended receiver. If the
receiver replies to this (benign looking) email, they unknowingly leak the
plaintext of the encrypted message part(s) back to the attacker
(CVE-2019-10732).");

  script_tag(name:"affected", value:"'messagelib' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecomposer5", rpm:"lib64kf5messagecomposer5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecore5", rpm:"lib64kf5messagecore5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelib-devel", rpm:"lib64kf5messagelib-devel~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelist5", rpm:"lib64kf5messagelist5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messageviewer5", rpm:"lib64kf5messageviewer5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5mimetreeparser5", rpm:"lib64kf5mimetreeparser5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5templateparser5", rpm:"lib64kf5templateparser5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5webengineviewer5", rpm:"lib64kf5webengineviewer5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecomposer5", rpm:"libkf5messagecomposer5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecore5", rpm:"libkf5messagecore5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelib-devel", rpm:"libkf5messagelib-devel~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelist5", rpm:"libkf5messagelist5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messageviewer5", rpm:"libkf5messageviewer5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5mimetreeparser5", rpm:"libkf5mimetreeparser5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5templateparser5", rpm:"libkf5templateparser5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5webengineviewer5", rpm:"libkf5webengineviewer5~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"messagelib", rpm:"messagelib~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
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
