# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122753");
  script_cve_id("CVE-2015-1345");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:27 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2111)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2111");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2111.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grep' package(s) announced via the ELSA-2015-2111 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.20-2]
- Fixed invalid UTF-8 byte sequence error in PCRE mode
 (by pcre-backported-fixes patch)
 Resolves: rhbz#1217080
- Fixed buffer overrun for grep -F
 Resolves: CVE-2015-1345
- Fixed \w and \W behaviour in multibyte locales
 Resolves: rhbz#1159012
- Documented --fixed-regexp option
 Resolves: rhbz#1103259
- Updated pcre buildrequires to require pcre-devel >= 7.8-7
 Related: rhbz#1217080");

  script_tag(name:"affected", value:"'grep' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"grep", rpm:"grep~2.20~2.el7", rls:"OracleLinux7"))) {
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
