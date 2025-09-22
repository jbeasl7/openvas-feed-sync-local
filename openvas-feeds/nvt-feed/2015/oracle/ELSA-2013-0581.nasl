# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123687");
  script_cve_id("CVE-2013-0338");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0581)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0581");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0581.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the ELSA-2013-0581 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.7.6-12.0.1.el6_4.1]
- Update doc/redhat.gif in tarball
- Add libxml2-oracle-enterprise.patch and update logos in tarball

[2.7.6-12.el6_4.1]
-detect and stop excessive entities expansion upon replacement (rhbz#912574)

[2.7.6-12.el6]
- fix out of range heap access (CVE-2012-5134)

[2.7.6-11.el6]
- Change the XPath code to percolate allocation error (CVE-2011-1944)

[2.7.6-10.el6]
- Fix an off by one pointer access (CVE-2011-3102)

[2.7.6-9.el6]
- Fix a failure to report xmlreader parsing failures
- Fix parser local buffers size problems (rhbz#843742)
- Fix entities local buffers size problems (rhbz#843742)
- Fix an error in previous commit (rhbz#843742)
- Do not fetch external parsed entities
- Impose a reasonable limit on attribute size (rhbz#843742)
- Impose a reasonable limit on comment size (rhbz#843742)
- Impose a reasonable limit on PI size (rhbz#843742)
- Cleanups and new limit APIs for dictionaries (rhbz#843742)
- Introduce some default parser limits (rhbz#843742)
- Implement some default limits in the XPath module
- Fixup limits parser (rhbz#843742)
- Enforce XML_PARSER_EOF state handling through the parser
- Avoid quadratic behaviour in some push parsing cases (rhbz#843742)
- More avoid quadratic behaviour (rhbz#843742)
- Strengthen behaviour of the push parser in problematic situations (rhbz#843742)
- More fixups on the push parser behaviour (rhbz#843742)
- Fix a segfault on XSD validation on pattern error
- Fix an unimplemented part in RNG value validation");

  script_tag(name:"affected", value:"'libxml2' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.21.0.1.el5_9.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.21.0.1.el5_9.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.21.0.1.el5_9.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.7.6~12.0.1.el6_4.1", rls:"OracleLinux6"))) {
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
