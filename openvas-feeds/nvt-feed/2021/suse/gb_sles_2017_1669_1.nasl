# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1669.1");
  script_cve_id("CVE-2016-10196", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469", "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7761", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7768", "CVE-2017-7778");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-13 17:14:37 +0000 (Mon, 13 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1669-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1669-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171669-1.html");
  script_xref(name:"URL", value:"http://www.unicode.org/reports/tr31/tr31-26");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043960");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002976.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLE' package(s) announced via the SUSE-SU-2017:1669-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The MozillaFirefox was updated to the new ESR 52.2 release, which fixes the following issues (bsc#1043960):

* MFSA 2017-16/CVE-2017-7758
 Out-of-bounds read in Opus encoder
* MFSA 2017-16/CVE-2017-7749
 Use-after-free during docshell reloading
* MFSA 2017-16/CVE-2017-7751
 Use-after-free with content viewer listeners
* MFSA 2017-16/CVE-2017-5472
 Use-after-free using destroyed node when regenerating trees
* MFSA 2017-16/CVE-2017-5470
 Memory safety bugs fixed in Firefox 54 and Firefox ESR 52.2
* MFSA 2017-16/CVE-2017-7752
 Use-after-free with IME input
* MFSA 2017-16/CVE-2017-7750
 Use-after-free with track elements
* MFSA 2017-16/CVE-2017-7768
 32 byte arbitrary file read through Mozilla Maintenance
 Service
* MFSA 2017-16/CVE-2017-7778
 Vulnerabilities in the Graphite 2 library
* MFSA 2017-16/CVE-2017-7754
 Out-of-bounds read in WebGL with ImageInfo object
* MFSA 2017-16/CVE-2017-7755
 Privilege escalation through Firefox Installer with same
 directory DLL files
* MFSA 2017-16/CVE-2017-7756
 Use-after-free and use-after-scope logging XHR header errors
* MFSA 2017-16/CVE-2017-7757
 Use-after-free in IndexedDB
* MFSA 2017-16/CVE-2017-7761
 File deletion and privilege escalation through Mozilla
 Maintenance Service helper.exe application
* MFSA 2017-16/CVE-2017-7763
 Mac fonts render some unicode characters as spaces
* MFSA 2017-16/CVE-2017-7765
 Mark of the Web bypass when saving executable files
* MFSA 2017-16/CVE-2017-7764
 (bmo#1364283, bmo#[link moved to references]
 .html#Aspirational_Use_Scripts)
 Domain spoofing with combination of Canadian Syllabics and
 other unicode blocks

- update to Firefox ESR 52.1 (bsc#1035082)
* MFSA 2017-12/CVE-2016-10196
 Vulnerabilities in Libevent library
* MFSA 2017-12/CVE-2017-5443
 Out-of-bounds write during BinHex decoding
* MFSA 2017-12/CVE-2017-5429
 Memory safety bugs fixed in Firefox 53, Firefox ESR 45.9, and
 Firefox ESR 52.1
* MFSA 2017-12/CVE-2017-5464
 Memory corruption with accessibility and DOM manipulation
* MFSA 2017-12/CVE-2017-5465
 Out-of-bounds read in ConvolvePixel
* MFSA 2017-12/CVE-2017-5466
 Origin confusion when reloading isolated data:text/html URL
* MFSA 2017-12/CVE-2017-5467
 Memory corruption when drawing Skia content
* MFSA 2017-12/CVE-2017-5460
 Use-after-free in frame selection
* MFSA 2017-12/CVE-2017-5461
 Out-of-bounds write in Base64 encoding in NSS
* MFSA 2017-12/CVE-2017-5448
 Out-of-bounds write in ClearKeyDecryptor
* MFSA 2017-12/CVE-2017-5449
 Crash during bidirectional unicode manipulation with
 animation
* MFSA 2017-12/CVE-2017-5446
 Out-of-bounds read when HTTP/2 DATA frames are sent with
 incorrect data
* MFSA 2017-12/CVE-2017-5447
 Out-of-bounds read during glyph processing
* MFSA 2017-12/CVE-2017-5444
 Buffer overflow while parsing application/http-index-format
 content
* MFSA 2017-12/CVE-2017-5445
 Uninitialized values used while parsing application/http-
 index-format content
* MFSA ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLE' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.2.0esr~108.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~52~31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~52.2.0esr~108.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.2.0esr~108.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.2.0esr~108.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~52~31.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~52.2.0esr~108.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.2.0esr~108.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.2.0esr~108.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~52~31.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.2.0esr~108.3", rls:"SLES12.0SP2"))) {
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
