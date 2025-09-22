# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120329");
  script_cve_id("CVE-2015-0243", "CVE-2015-0244");
  script_tag(name:"creation_date", value:"2015-09-08 11:23:42 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 20:18:00 +0000 (Fri, 31 Jan 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-485");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-485.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93' package(s) announced via the ALAS-2015-485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto module. An authenticated database user could use this flaw to cause PostgreSQL to crash or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in way PostgreSQL handled certain errors during that were generated during protocol synchronization. An authenticated database user could use this flaw to inject queries into an existing connection. (CVE-2015-0244)");

  script_tag(name:"affected", value:"'postgresql93' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-devel", rpm:"postgresql93-devel~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-libs", rpm:"postgresql93-libs~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plperl", rpm:"postgresql93-plperl~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-plpython", rpm:"postgresql93-plpython~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-pltcl", rpm:"postgresql93-pltcl~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-test", rpm:"postgresql93-test~9.3.6~1.56.amzn1", rls:"AMAZON"))) {
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
