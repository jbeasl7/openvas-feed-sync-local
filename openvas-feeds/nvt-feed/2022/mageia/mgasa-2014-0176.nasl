# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0176");
  script_cve_id("CVE-2013-7176", "CVE-2013-7177");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0176");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0176.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00021.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11569");
  script_xref(name:"URL", value:"https://github.com/fail2ban/fail2ban/releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fail2ban' package(s) announced via the MGASA-2014-0176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An update to fail2ban 0.8.13 has been released to fix security issues,
amongst other bugfixes.

fail2ban versions prior to 0.8.11 would allow a remote unauthenticated
attacker to cause arbitrary IP addresses to be blocked by Fail2ban causing
legitimate users to be blocked from accessing services protected by
Fail2ban. These services are cyrus-imap (CVE-2013-7177) and postfix
(CVE-2013-7176).");

  script_tag(name:"affected", value:"'fail2ban' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"fail2ban", rpm:"fail2ban~0.8.13~2.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"fail2ban", rpm:"fail2ban~0.8.13~2.mga4", rls:"MAGEIA4"))) {
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
