# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0425");
  script_cve_id("CVE-2020-24972");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-03 17:58:34 +0000 (Thu, 03 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0425)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0425");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0425.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27455");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IRIPL72WMXTVWS2M7WYV5SNPETYJ2YI7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kleopatra' package(s) announced via the MGASA-2020-0425 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Kleopatra component before 20.07.80 for GnuPG allows remote attackers to
execute arbitrary code because openpgp4fpr: URLs are supported without safe
handling of command-line options. The Qt platformpluginpath command-line
option can be used to load an arbitrary library.
(CVE-2020-24972).");

  script_tag(name:"affected", value:"'kleopatra' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"kleopatra", rpm:"kleopatra~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kleopatra-handbook", rpm:"kleopatra-handbook~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5kleopatraclientcore1", rpm:"lib64kf5kleopatraclientcore1~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5kleopatraclientgui1", rpm:"lib64kf5kleopatraclientgui1~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5libkleopatra-devel", rpm:"lib64kf5libkleopatra-devel~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5kleopatraclientcore1", rpm:"libkf5kleopatraclientcore1~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5kleopatraclientgui1", rpm:"libkf5kleopatraclientgui1~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5libkleopatra-devel", rpm:"libkf5libkleopatra-devel~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
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
