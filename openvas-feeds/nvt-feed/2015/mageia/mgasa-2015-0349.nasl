# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130038");
  script_cve_id("CVE-2015-2059");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:51 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0349)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0349");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0349.html");
  script_xref(name:"URL", value:"http://lists.gnu.org/archive/html/info-gnu/2015-03/msg00000.html");
  script_xref(name:"URL", value:"http://lists.gnu.org/archive/html/info-gnu/2015-07/msg00003.html");
  script_xref(name:"URL", value:"http://lists.gnu.org/archive/html/info-gnu/2015-08/msg00000.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-07/msg00042.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16342");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libidn' package(s) announced via the MGASA-2015-0349 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libidn packages fix security vulnerability:

In libidn before 1.31, stringprep_utf8_to_ucs4 did not validate that the input
UTF-8 string was actually valid UTF-8, which could lead to out-of-bounds
reads (CVE-2015-2059).");

  script_tag(name:"affected", value:"'libidn' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"idn", rpm:"idn~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn-devel", rpm:"lib64idn-devel~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn11", rpm:"lib64idn11~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn11-java", rpm:"lib64idn11-java~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn11-mono", rpm:"lib64idn11-mono~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn", rpm:"libidn~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn-devel", rpm:"libidn-devel~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn11", rpm:"libidn11~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn11-java", rpm:"libidn11-java~1.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn11-mono", rpm:"libidn11-mono~1.32~1.mga5", rls:"MAGEIA5"))) {
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
