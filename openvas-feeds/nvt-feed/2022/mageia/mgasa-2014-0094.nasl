# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0094");
  script_cve_id("CVE-2014-1471", "CVE-2014-1694");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0094)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0094");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0094.html");
  script_xref(name:"URL", value:"http://www.otrs.com/release_notes_otrs_help_desk_3_2_14/");
  script_xref(name:"URL", value:"http://www.otrs.com/security-advisory-2014-01-csrf-issue-customer-web-interface/");
  script_xref(name:"URL", value:"http://www.otrs.com/security-advisory-2014-02-sql-injection-issue/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10669");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12473");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'otrs' package(s) announced via the MGASA-2014-0094 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated otrs package fixes security vulnerabilities:

In OTRS before 3.2.14, an attacker that managed to take over the session of a
logged in customer could create tickets and/or send follow-ups to existing
tickets due to missing challenge token checks (CVE-2014-1694).

In OTRS before 3.2.14, an attacker with a valid customer or agent login could
inject SQL in the ticket search URL (CVE-2014-1471).

The update also adds a missing dependency which prevented database creation
during web based installation.");

  script_tag(name:"affected", value:"'otrs' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.2.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.2.14~1.mga4", rls:"MAGEIA4"))) {
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
