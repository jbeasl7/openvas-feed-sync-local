# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0402");
  script_cve_id("CVE-2018-16741", "CVE-2018-16742", "CVE-2018-16743", "CVE-2018-16744", "CVE-2018-16745");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 17:08:56 +0000 (Thu, 01 Nov 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0402)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0402");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0402.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23567");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-09/msg00176.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mgetty' package(s) announced via the MGASA-2018-0402 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mgetty packages fix security vulnerabilities:

The function do_activate() did not properly sanitize shell metacharacters
to prevent command injection (CVE-2018-16741).

Stack-based buffer overflow that could have been triggered via a
command-line parameter (CVE-2018-16742).

The command-line parameter username wsa passed unsanitized to strcpy(),
which could have caused a stack-based buffer overflow (CVE-2018-16743).

The mail_to parameter was not sanitized, leading to command injection if
untrusted input reached reach it (CVE-2018-16744).

The mail_to parameter was not sanitized, leading to a buffer overflow if
long untrusted input reached it (CVE-2018-16745).");

  script_tag(name:"affected", value:"'mgetty' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"mgetty", rpm:"mgetty~1.1.37~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgetty-contrib", rpm:"mgetty-contrib~1.1.37~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgetty-sendfax", rpm:"mgetty-sendfax~1.1.37~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgetty-viewfax", rpm:"mgetty-viewfax~1.1.37~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgetty-voice", rpm:"mgetty-voice~1.1.37~1.1.mga6", rls:"MAGEIA6"))) {
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
