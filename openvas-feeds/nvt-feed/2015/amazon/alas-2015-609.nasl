# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120599");
  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_tag(name:"creation_date", value:"2015-11-08 11:11:01 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-609)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-609");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-609.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql92, postgresql93, postgresql94' package(s) announced via the ALAS-2015-609 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple stack-based buffer overflows in json parsing in PostgreSQL before 9.3.x before 9.3.10 and 9.4.x before 9.4.5 allow attackers to cause a denial of service (server crash) via unspecified vectors, which are not properly handled in (1) json or (2) jsonb values. (CVE-2015-5289)

The crypt function in contrib/pgcrypto in PostgreSQL before 9.0.23, 9.1.x before 9.1.19, 9.2.x before 9.2.14, 9.3.x before 9.3.10, and 9.4.x before 9.4.5 allows attackers to cause a denial of service (server crash) or read arbitrary server memory via a 'too-short' salt. (CVE-2015-5288)");

  script_tag(name:"affected", value:"'postgresql92, postgresql93, postgresql94' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql92", rpm:"postgresql92~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-contrib", rpm:"postgresql92-contrib~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-debuginfo", rpm:"postgresql92-debuginfo~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-devel", rpm:"postgresql92-devel~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-docs", rpm:"postgresql92-docs~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-libs", rpm:"postgresql92-libs~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-plperl", rpm:"postgresql92-plperl~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-plpython26", rpm:"postgresql92-plpython26~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-plpython27", rpm:"postgresql92-plpython27~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-pltcl", rpm:"postgresql92-pltcl~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-server", rpm:"postgresql92-server~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-server-compat", rpm:"postgresql92-server-compat~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-test", rpm:"postgresql92-test~9.2.14~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-devel", rpm:"postgresql93-devel~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-libs", rpm:"postgresql93-libs~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plperl", rpm:"postgresql93-plperl~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plpython26", rpm:"postgresql93-plpython26~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plpython27", rpm:"postgresql93-plpython27~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-pltcl", rpm:"postgresql93-pltcl~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-test", rpm:"postgresql93-test~9.3.10~1.60.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-debuginfo", rpm:"postgresql94-debuginfo~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-devel", rpm:"postgresql94-devel~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-libs", rpm:"postgresql94-libs~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plperl", rpm:"postgresql94-plperl~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plpython26", rpm:"postgresql94-plpython26~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-plpython27", rpm:"postgresql94-plpython27~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-pltcl", rpm:"postgresql94-pltcl~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-test", rpm:"postgresql94-test~9.4.5~1.63.amzn1", rls:"AMAZON"))) {
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
