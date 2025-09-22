# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0185");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0185)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0185");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0185.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0315.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0481.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2015-0055.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15391");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hiawatha, polarssl' package(s) announced via the MGASA-2015-0185 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated hiawatha package fixes security vulnerabilities:

The hiawatha package included a bundled copy of PolarSSL 1.3.2, which was
vulnerable to several security issues that had already been fixed in the
system polarssl package. These issues were CVE-2014-4911, CVE-2014-8627,
CVE-2014-8628, and CVE-2015-1182, which were fixed in MGASA-2014-0315,
MGASA-2014-0481, and MGASA-2015-0055.

The polarssl package has been adjusted so that hiawatha can use it, and
hiawatha has been rebuilt to use the updated system polarssl, fixing these
issues.");

  script_tag(name:"affected", value:"'hiawatha, polarssl' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"hiawatha", rpm:"hiawatha~9.3~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl-devel", rpm:"lib64polarssl-devel~1.3.9~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl7", rpm:"lib64polarssl7~1.3.9~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl-devel", rpm:"libpolarssl-devel~1.3.9~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl7", rpm:"libpolarssl7~1.3.9~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polarssl", rpm:"polarssl~1.3.9~1.2.mga4", rls:"MAGEIA4"))) {
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
