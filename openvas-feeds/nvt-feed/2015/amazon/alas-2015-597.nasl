# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120217");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"creation_date", value:"2015-09-25 08:17:59 +0000 (Fri, 25 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-597)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-597");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-597.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont' package(s) announced via the ALAS-2015-597 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw was found in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server or, potentially, execute arbitrary code with the privileges of the X.Org server. (CVE-2015-1802)

An integer truncation flaw was discovered in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server or, potentially, execute arbitrary code with the privileges of the X.Org server. (CVE-2015-1804)

A NULL pointer dereference flaw was discovered in the way libXfont processed certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could use this flaw to crash the X.Org server. (CVE-2015-1803)");

  script_tag(name:"affected", value:"'libXfont' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.5~5.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.4.5~5.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.5~5.12.amzn1", rls:"AMAZON"))) {
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
