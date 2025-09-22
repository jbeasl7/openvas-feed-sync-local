# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0127");
  script_cve_id("CVE-2013-4407");
  script_tag(name:"creation_date", value:"2024-04-15 04:26:26 +0000 (Mon, 15 Apr 2024)");
  script_version("2024-04-15T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-04-15 05:05:35 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2024-0127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0127");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0127.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33067");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/04/07/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-HTTP-Body' package(s) announced via the MGASA-2024-0127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTTP::Body::Multipart in the HTTP-Body 1.08, 1.17, and earlier module
for Perl uses the part of the uploaded file's name after the first '.'
character as the suffix of a temporary file, which makes it easier for
remote attackers to conduct attacks by leveraging subsequent behavior
that may assume the suffix is well-formed. (CVE-2013-4407)");

  script_tag(name:"affected", value:"'perl-HTTP-Body' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-Body", rpm:"perl-HTTP-Body~1.230.0~1.mga9", rls:"MAGEIA9"))) {
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
