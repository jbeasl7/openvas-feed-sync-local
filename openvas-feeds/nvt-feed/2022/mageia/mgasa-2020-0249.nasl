# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0249");
  script_cve_id("CVE-2019-19274", "CVE-2019-19275");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-09 17:24:47 +0000 (Mon, 09 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0249");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0249.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26590");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2020-05/msg00001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-typed-ast' package(s) announced via the MGASA-2020-0249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-typed-ast package fixes security vulnerabilities:

typed_ast 1.3.0 and 1.3.1 has a handle_keywordonly_args out-of-bounds
read. An attacker with the ability to cause a Python interpreter to
parse Python source (but not necessarily execute it) may be able to crash
the interpreter process. This could be a concern, for example, in a
web-based service that parses (but does not execute) Python code
(CVE-2019-19274).

typed_ast 1.3.0 and 1.3.1 has an ast_for_arguments out-of-bounds read. An
attacker with the ability to cause a Python interpreter to parse Python
source but not necessarily execute it) may be able to crash the
interpreter process. This could be a concern, for example, in a web-based
service that parses (but does not execute) Python code (CVE-2019-19275).");

  script_tag(name:"affected", value:"'python-typed-ast' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-typed-ast", rpm:"python-typed-ast~1.3.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-typed-ast", rpm:"python3-typed-ast~1.3.1~1.1.mga7", rls:"MAGEIA7"))) {
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
