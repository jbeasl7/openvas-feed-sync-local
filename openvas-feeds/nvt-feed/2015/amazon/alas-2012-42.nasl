# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120257");
  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:42 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-42)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-42");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-42.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the ALAS-2012-42 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw was found in Ghostscript's TrueType bytecode interpreter. An attacker could create a specially-crafted PostScript or PDF file that, when interpreted, could cause Ghostscript to crash or, potentially, execute arbitrary code. (CVE-2009-3743)

It was found that Ghostscript always tried to read Ghostscript system initialization files from the current working directory before checking other directories, even if a search path that did not contain the current working directory was specified with the '-I' option, or the '-P-' option was used (to prevent the current working directory being searched first). If a user ran Ghostscript in an attacker-controlled directory containing a system initialization file, it could cause Ghostscript to execute arbitrary PostScript code. (CVE-2010-2055)

Ghostscript included the current working directory in its library search path by default. If a user ran Ghostscript without the '-P-' option in an attacker-controlled directory containing a specially-crafted PostScript library file, it could cause Ghostscript to execute arbitrary PostScript code. With this update, Ghostscript no longer searches the current working directory for library files by default. (CVE-2010-4820)

Note: The fix for CVE-2010-4820 could possibly break existing configurations. To use the previous, vulnerable behavior, run Ghostscript with the '-P' option (to always search the current working directory first).

A flaw was found in the way Ghostscript interpreted PostScript Type 1 and PostScript Type 2 font files. An attacker could create a specially-crafted PostScript Type 1 or PostScript Type 2 font file that, when interpreted, could cause Ghostscript to crash or, potentially, execute arbitrary code. (CVE-2010-4054)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.70~11.20.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~8.70~11.20.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~8.70~11.20.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.70~11.20.amzn1", rls:"AMAZON"))) {
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
