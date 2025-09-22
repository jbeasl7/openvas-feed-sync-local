# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120259");
  script_cve_id("CVE-2010-2642", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:48 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-48)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-48");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-48.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive' package(s) announced via the ALAS-2012-48 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"TeX Live embeds a copy of t1lib. The t1lib library allows you to rasterize bitmaps from PostScript Type 1 fonts. The following issues affect t1lib code:

Two heap-based buffer overflow flaws were found in the way t1lib processed Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened by a TeX Live utility, it could cause the utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2010-2642, CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash or, potentially, execute arbitrary code with the privileges of the user running the utility. (CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially-crafted font file could, when opened, cause a TeX Live utility to crash. (CVE-2011-1552)");

  script_tag(name:"affected", value:"'texlive' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"kpathsea", rpm:"kpathsea~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kpathsea-devel", rpm:"kpathsea-devel~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mendexk", rpm:"mendexk~2.6e~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive", rpm:"texlive~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm", rpm:"texlive-afm~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-context", rpm:"texlive-context~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debuginfo", rpm:"texlive-debuginfo~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips", rpm:"texlive-dvips~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviutils", rpm:"texlive-dviutils~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-east-asian", rpm:"texlive-east-asian~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex", rpm:"texlive-latex~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-utils", rpm:"texlive-utils~2007~57.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex", rpm:"texlive-xetex~2007~57.9.amzn1", rls:"AMAZON"))) {
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
