# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0551");
  script_cve_id("CVE-2014-3604");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0551)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0551");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0551.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14175");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138550.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'not-yet-commons-ssl' package(s) announced via the MGASA-2014-0551 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated not-yet-commons-ssl packages fixes security vulnerability:

It was discovered that the implementation used by the Not Yet Commons SSL
project to check that the server hostname matches the domain name in the
subject's CN field was flawed. This can be exploited by a Man-in-the-middle
(MITM) attack, where the attacker can spoof a valid certificate using a
specially crafted subject (CVE-2014-3604).");

  script_tag(name:"affected", value:"'not-yet-commons-ssl' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"not-yet-commons-ssl", rpm:"not-yet-commons-ssl~0.3.15~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"not-yet-commons-ssl-javadoc", rpm:"not-yet-commons-ssl-javadoc~0.3.15~1.mga4", rls:"MAGEIA4"))) {
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
