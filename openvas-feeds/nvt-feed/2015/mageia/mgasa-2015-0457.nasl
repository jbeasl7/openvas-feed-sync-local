# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131140");
  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317", "CVE-2015-8710");
  script_tag(name:"creation_date", value:"2015-11-27 09:00:03 +0000 (Fri, 27 Nov 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-13 18:22:02 +0000 (Wed, 13 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0457)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0457");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0457.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/11/18/23");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/11/22/3");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2875-1/");
  script_xref(name:"URL", value:"http://www.xmlsoft.org/news.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17170");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the MGASA-2015-0457 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libxml2 packages fix security vulnerabilities:

In libxml2 before 2.9.3, one case where when dealing with entities expansion,
it failed to exit, leading to a denial of service (CVE-2015-5312).

In libxml2 before 2.9.3, it was possible to hit a negative offset in the name
indexing used to randomize the dictionary key generation, causing a heap
buffer overflow in xmlDictComputeFastQKey (CVE-2015-7497).

In libxml2 before 2.9.3, after encoding conversion failures, the parser was
continuing to process to extract more errors, which can potentially lead to
unexpected behaviour (CVE-2015-7498).

In libxml2 before 2.9.3, the parser failed to detect a case where the current
pointer to the input was out of range, leaving it in an incoherent state
(CVE-2015-7499).

In libxml2 before 2.9.3, a memory access error could happen while processing
a start tag due to incorrect entities boundaries (CVE-2015-7500).

In libxml2 before 2.9.3, a buffer overread in xmlNextChar due to extra
processing of MarkupDecl after EOF has been reached (CVE-2015-8241).

In libxml2 before 2.9.3, stack-basedb uffer overead with HTML parser in push
mode (CVE-2015-8242).

In libxml2 before 2.9.3, out of bounds heap reads could happen due to failure
processing the encoding declaration of the XMLDecl in xmlParseEncodingDecl
(CVE-2015-8317).

In libxml2 before 2.9.3, out of bounds memory access via unclosed html
comment (CVE-2015-8710).");

  script_tag(name:"affected", value:"'libxml2' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2-devel", rpm:"lib64xml2-devel~2.9.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2_2", rpm:"lib64xml2_2~2.9.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.9.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-utils", rpm:"libxml2-utils~2.9.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2_2", rpm:"libxml2_2~2.9.3~1.mga5", rls:"MAGEIA5"))) {
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
