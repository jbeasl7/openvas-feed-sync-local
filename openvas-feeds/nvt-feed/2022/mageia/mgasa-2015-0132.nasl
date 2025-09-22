# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0132");
  script_cve_id("CVE-2015-2265");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0132)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0132");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0132.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2532-1/");
  script_xref(name:"URL", value:"https://bugs.linuxfoundation.org/show_bug.cgi?id=1265");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15424");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters' package(s) announced via the MGASA-2015-0132 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cups-filters package fixes security vulnerability:

cups-browsed in cups-filters before 1.0.66 contained a bug in the
remove_bad_chars() function, where it failed to reliably filter out illegal
characters if there were two or more subsequent illegal characters, allowing
execution of arbitrary commands with the rights of the 'lp' user, using forged
print service announcements on DNS-SD servers (CVE-2015-2265).");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.53~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters-devel", rpm:"lib64cups-filters-devel~1.0.53~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters1", rpm:"lib64cups-filters1~1.0.53~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters-devel", rpm:"libcups-filters-devel~1.0.53~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters1", rpm:"libcups-filters1~1.0.53~1.1.mga4", rls:"MAGEIA4"))) {
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
