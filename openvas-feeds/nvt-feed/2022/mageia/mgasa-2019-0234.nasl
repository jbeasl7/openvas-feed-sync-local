# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0234");
  script_cve_id("CVE-2019-10156");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:23:00 +0000 (Tue, 06 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0234)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0234");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0234.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25285");
  script_xref(name:"URL", value:"https://github.com/ansible/ansible/blob/stable-2.7/changelogs/CHANGELOG-v2.7.rst");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4072-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible, python-jmespath' package(s) announced via the MGASA-2019-0234 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ansible package fixes security vulnerability:

A flaw was discovered in the way Ansible templating was implemented before
version 2.7.12, causing the possibility of information disclosure through
unexpected variable substitution. By taking advantage of unintended variable
substitution the content of any variable may be disclosed (CVE-2019-10156).

Also, python-jmespath was added as a new dependency in Mageia 6.");

  script_tag(name:"affected", value:"'ansible, python-jmespath' package(s) on Mageia 6, Mageia 7.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.7.12~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jmespath", rpm:"python-jmespath~0.9.4~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jmespath", rpm:"python3-jmespath~0.9.4~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.7.12~1.mga7", rls:"MAGEIA7"))) {
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
