# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0535");
  script_cve_id("CVE-2013-4440", "CVE-2013-4442");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0535");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0535.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14809");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146237.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pwgen' package(s) announced via the MGASA-2014-0535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated pwgen package fixes security vulnerabilities:

Pwgen was found to generate weak non-tty passwords by default, which could
be brute-forced with a commendable success rate, which could raise security
concerns (CVE-2013-4440).

Pwgen was found to silently falling back to use standard pseudo generated
numbers on the systems that heavily use entropy. Systems, such as those with
a lot of daemons providing encryption services, the entropy was found to be
exhausted, which forces pwgen to fall back to use standard pseudo generated
numbers (CVE-2013-4442).");

  script_tag(name:"affected", value:"'pwgen' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"pwgen", rpm:"pwgen~2.07~1.mga4", rls:"MAGEIA4"))) {
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
