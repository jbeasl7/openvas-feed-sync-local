# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120487");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"creation_date", value:"2015-09-08 11:27:35 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:22:42 +0000 (Thu, 15 Feb 2024)");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-129");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-129.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql8' package(s) announced via the ALAS-2012-129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the optional PostgreSQL xml2 contrib module allowed local files and remote URLs to be read and written to with the privileges of the database server when parsing Extensible Stylesheet Language Transformations (XSLT). An unprivileged database user could use this flaw to read and write to local files (such as the database's configuration files) and remote URLs they would otherwise not have access to by issuing a specially-crafted SQL query. (CVE-2012-3488)

It was found that the 'xml' data type allowed local files and remote URLs to be read with the privileges of the database server to resolve DTD and entity references in the provided XML. An unprivileged database user could use this flaw to read local files they would otherwise not have access to by issuing a specially-crafted SQL query. Note that the full contents of the files were not returned, but portions could be displayed to the user via error messages. (CVE-2012-3489)");

  script_tag(name:"affected", value:"'postgresql8' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql8", rpm:"postgresql8~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-contrib", rpm:"postgresql8-contrib~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-debuginfo", rpm:"postgresql8-debuginfo~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-devel", rpm:"postgresql8-devel~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-docs", rpm:"postgresql8-docs~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-libs", rpm:"postgresql8-libs~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-plperl", rpm:"postgresql8-plperl~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-plpython", rpm:"postgresql8-plpython~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-pltcl", rpm:"postgresql8-pltcl~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-server", rpm:"postgresql8-server~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql8-test", rpm:"postgresql8-test~8.4.13~1.37.amzn1", rls:"AMAZON"))) {
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
