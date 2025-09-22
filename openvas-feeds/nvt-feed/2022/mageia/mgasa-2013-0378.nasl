# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0378");
  script_cve_id("CVE-2013-6048", "CVE-2013-6359");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0378)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0378");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0378.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2815");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11944");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'munin' package(s) announced via the MGASA-2013-0378 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated munin packages fix security vulnerabilities:

The Munin::Master::Node module of munin does not properly validate certain
data a node sends. A malicious node might exploit this to drive the munin-html
process into an infinite loop with memory exhaustion on the munin master
(CVE-2013-6048).

A malicious node, with a plugin enabled using 'multigraph' as a multigraph
service name, can abort data collection for the entire node the plugin runs on
(CVE-2013-6359).");

  script_tag(name:"affected", value:"'munin' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"munin", rpm:"munin~2.0.12~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"munin-async", rpm:"munin-async~2.0.12~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"munin-java-plugins", rpm:"munin-java-plugins~2.0.12~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"munin-master", rpm:"munin-master~2.0.12~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"munin-node", rpm:"munin-node~2.0.12~2.1.mga3", rls:"MAGEIA3"))) {
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
