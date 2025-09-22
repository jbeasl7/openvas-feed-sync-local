# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1915.1");
  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2015-1774", "CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1915-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1915-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151915-1.html");
  script_xref(name:"URL", value:"http://www.libreoffice.org/discover/new-features/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/470073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/86241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/87222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945692");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-November/001669.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice' package(s) announced via the SUSE-SU-2015:1915-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update brings LibreOffice to version 5.0.2, a major version update.

It brings lots of new features, bugfixes and also security fixes.

Features as seen on [link moved to references]

* LibreOffice 5.0 ships an impressive number of new features for
 its spreadsheet module, Calc: complex formulae image cropping, new
 functions, more powerful conditional formatting, table addressing
 and much more. Calc's blend of performance and features makes it
 an enterprise-ready, heavy duty spreadsheet application capable of
 handling all kinds of workload for an impressive range of use cases
* New icons, major improvements to menus and sidebar : no other
 LibreOffice version has looked that good and helped you be creative and
 get things done the right way. In addition, style management is now more
 intuitive thanks to the visualization of styles right in the interface.
* LibreOffice 5 ships with numerous improvements to document import and
 export filters for MS Office, PDF, RTF, and more. You can now timestamp
 PDF documents generated with LibreOffice and enjoy enhanced document
 conversion fidelity all around.

The Pentaho Flow Reporting Engine is now added and used.

Security issues fixed:

* CVE-2014-8146: The resolveImplicitLevels function in common/ubidi.c
 in the Unicode Bidirectional Algorithm implementation in ICU4C in
 International Components for Unicode (ICU) before 55.1 did not properly
 track directionally isolated pieces of text, which allowed remote
 attackers to cause a denial of service (heap-based buffer overflow)
 or possibly execute arbitrary code via crafted text.
* CVE-2014-8147: The resolveImplicitLevels function in common/ubidi.c
 in the Unicode Bidirectional Algorithm implementation in ICU4C in
 International Components for Unicode (ICU) before 55.1 used an integer
 data type that is inconsistent with a header file, which allowed remote
 attackers to cause a denial of service (incorrect malloc followed by
 invalid free) or possibly execute arbitrary code via crafted text.
* CVE-2015-4551: An arbitrary file disclosure vulnerability in Libreoffice
 and Openoffice Calc and Writer was fixed.
* CVE-2015-1774: The HWP filter in LibreOffice allowed remote attackers
 to cause a denial of service (crash) or possibly execute arbitrary code
 via a crafted HWP document, which triggered an out-of-bounds write.
* CVE-2015-5212: A LibreOffice 'PrinterSetup Length' integer underflow
 vulnerability could be used by attackers supplying documents to execute
 code as the user opening the document.
* CVE-2015-5213: A LibreOffice 'Piece Table Counter' invalid check design
 error vulnerability allowed attackers supplying documents to execute
 code as the user opening the document.
* CVE-2015-5214: Multiple Vendor LibreOffice Bookmark Status Memory
 Corruption Vulnerability allowed attackers supplying documents to execute
 code as the user opening the document.");

  script_tag(name:"affected", value:"'LibreOffice' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-logging", rpm:"apache-commons-logging~1.1.3~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphite2-3", rpm:"libgraphite2-3~1.3.1~3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphite2-3-32bit", rpm:"libgraphite2-3-32bit~1.3.1~3.1", rls:"SLES12.0"))) {
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
