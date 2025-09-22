# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63955");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_tag(name:"creation_date", value:"2009-05-11 18:24:31 +0000 (Mon, 11 May 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1790-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1790-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1790-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1790");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xpdf' package(s) announced via the DSA-1790-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in xpdf, a suite of tools for viewing and converting Portable Document Format (PDF) files.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0146

Multiple buffer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, and other products allow remote attackers to cause a denial of service (crash) via a crafted PDF file, related to (1) JBIG2SymbolDict::setBitmap and (2) JBIG2Stream::readSymbolDictSeg.

CVE-2009-0147

Multiple integer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, and other products allow remote attackers to cause a denial of service (crash) via a crafted PDF file, related to (1) JBIG2Stream::readSymbolDictSeg, (2) JBIG2Stream::readSymbolDictSeg, and (3) JBIG2Stream::readGenericBitmap.

CVE-2009-0165

Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier, as used in Poppler and other products, when running on Mac OS X, has unspecified impact, related to 'g*allocn.'

CVE-2009-0166

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, and other products allows remote attackers to cause a denial of service (crash) via a crafted PDF file that triggers a free of uninitialized memory.

CVE-2009-0799

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allows remote attackers to cause a denial of service (crash) via a crafted PDF file that triggers an out-of-bounds read.

CVE-2009-0800

Multiple 'input validation flaws' in the JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allow remote attackers to execute arbitrary code via a crafted PDF file.

CVE-2009-1179

Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allows remote attackers to execute arbitrary code via a crafted PDF file.

CVE-2009-1180

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allows remote attackers to execute arbitrary code via a crafted PDF file that triggers a free of invalid data.

CVE-2009-1181

The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allows remote attackers to cause a denial of service (crash) via a crafted PDF file that triggers a NULL pointer dereference.

CVE-2009-1182

Multiple buffer overflows in the JBIG2 MMR decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allow remote attackers to execute arbitrary code via a crafted PDF file.

CVE-2009-1183

The JBIG2 MMR decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products allows remote attackers to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xpdf' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"xpdf", ver:"3.01-9.1+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-common", ver:"3.01-9.1+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.01-9.1+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.01-9.1+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4+lenny1", rls:"DEB5"))) {
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
