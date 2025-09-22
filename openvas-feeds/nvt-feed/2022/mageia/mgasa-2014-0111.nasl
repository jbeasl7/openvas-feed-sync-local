# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0111");
  script_cve_id("CVE-2013-4376");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0111)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0111");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0111.html");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-201310-19.xml");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11557");
  script_xref(name:"URL", value:"https://lists.berlios.de/pipermail/x2go-announcement/2013-May/000125.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126414.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'x2goserver' package(s) announced via the MGASA-2014-0111 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in x2goserver before 4.0.0.2 in the setgid wrapper
x2gosqlitewrapper.c, which does not hardcode an internal path to
x2gosqlitewrapper.pl, allowing a remote attacker to change that path.
A remote attacker may be able to execute arbitrary code with the
privileges of the user running the server process (CVE-2013-4376).

A vulnerability in x2goserver before 4.0.0.8 in x2gocleansessions has
also been fixed.");

  script_tag(name:"affected", value:"'x2goserver' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"x2goserver", rpm:"x2goserver~4.0.1.13~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x2goserver-postgresql", rpm:"x2goserver-postgresql~4.0.1.13~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x2goserver-sqlite", rpm:"x2goserver-sqlite~4.0.1.13~1.mga3", rls:"MAGEIA3"))) {
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
