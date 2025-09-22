# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0018");
  script_cve_id("CVE-2020-28366", "CVE-2020-28367");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 15:55:46 +0000 (Tue, 24 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0018");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0018.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27650");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/F3ZSHGNTJWCWYAKY5OLZS2XQQYHSXSUO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2021-0018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An input validation vulnerability was found in go. From a generated go file
(from the cgo tool) it is possible to modify symbols within that object file
and specify code instead. An attacker could potentially use this flaw by
creating a repository which included malicious pre-built object files that
could execute arbitrary code when downloaded and run via 'go get' or 'go build'
whilst building a go project (CVE-2020-28366).

An input validation vulnerability was found in go. If cgo is specified in a go
file, it is possible to bypass the validation of arguments to the gcc compiler.
An attacker could potentially use this flaw by creating a malicious repository
which would execute arbitrary code when downloaded and run via 'go get' or
'go build' whilst building a go project (CVE-2020-28367).");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.13.15~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.13.15~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.13.15~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.13.15~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.13.15~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.13.15~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.13.15~3.mga7", rls:"MAGEIA7"))) {
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
