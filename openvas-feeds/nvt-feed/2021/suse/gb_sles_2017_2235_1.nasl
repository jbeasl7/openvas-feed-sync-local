# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2235.1");
  script_cve_id("CVE-2015-5276", "CVE-2016-10196", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469", "CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7761", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7768", "CVE-2017-7778");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-13 17:14:37 +0000 (Mon, 13 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2235-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2235-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172235-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968771");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003150.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLED, firefox-gcc5, mozilla-nss' package(s) announced via the SUSE-SU-2017:2235-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox and mozilla-nss fixes the following issues:

Security issues fixed:
- Fixes in Firefox ESR 52.2 (bsc#1043960,MFSA 2017-16)
 - CVE-2017-7758: Out-of-bounds read in Opus encoder
 - CVE-2017-7749: Use-after-free during docshell reloading
 - CVE-2017-7751: Use-after-free with content viewer listeners
 - CVE-2017-5472: Use-after-free using destroyed node when regenerating trees
 - CVE-2017-5470: Memory safety bugs fixed in Firefox 54 and Firefox ESR 52.2
 - CVE-2017-7752: Use-after-free with IME input
 - CVE-2017-7750: Use-after-free with track elements
 - CVE-2017-7768: 32 byte arbitrary file read through Mozilla Maintenance Service
 - CVE-2017-7778: Vulnerabilities in the Graphite 2 library
 - CVE-2017-7754: Out-of-bounds read in WebGL with ImageInfo object
 - CVE-2017-7755: Privilege escalation through Firefox Installer with same directory DLL files
 - CVE-2017-7756: Use-after-free and use-after-scope logging XHR header errors
 - CVE-2017-7757: Use-after-free in IndexedDB
 - CVE-2017-7761: File deletion and privilege escalation through Mozilla Maintenance Service helper.exe application
 - CVE-2017-7763: Mac fonts render some unicode characters as spaces
 - CVE-2017-7765: Mark of the Web bypass when saving executable files
 - CVE-2017-7764: Domain spoofing with combination of Canadian Syllabics and other unicode blocks

- update to Firefox ESR 52.1 (bsc#1035082,MFSA 2017-12)
 - CVE-2016-10196: Vulnerabilities in Libevent library
 - CVE-2017-5443: Out-of-bounds write during BinHex decoding
 - CVE-2017-5429: Memory safety bugs fixed in Firefox 53, Firefox ESR 45.9, and Firefox ESR 52.1
 - CVE-2017-5464: Memory corruption with accessibility and DOM manipulation
 - CVE-2017-5465: Out-of-bounds read in ConvolvePixel
 - CVE-2017-5466: Origin confusion when reloading isolated data:text/html URL
 - CVE-2017-5467: Memory corruption when drawing Skia content
 - CVE-2017-5460: Use-after-free in frame selection
 - CVE-2017-5461: Out-of-bounds write in Base64 encoding in NSS
 - CVE-2017-5448: Out-of-bounds write in ClearKeyDecryptor
 - CVE-2017-5449: Crash during bidirectional unicode manipulation with animation
 - CVE-2017-5446: Out-of-bounds read when HTTP/2 DATA frames are sent with incorrect data
 - CVE-2017-5447: Out-of-bounds read during glyph processing
 - CVE-2017-5444: Buffer overflow while parsing application/http-index-format content
 - CVE-2017-5445: Uninitialized values used while parsing application/http- index-format content
 - CVE-2017-5442: Use-after-free during style changes
 - CVE-2017-5469: Potential Buffer overflow in flex-generated code
 - CVE-2017-5440: Use-after-free in txExecutionState destructor during XSLT processing
 - CVE-2017-5441: Use-after-free with selection during scroll events
 - CVE-2017-5439: Use-after-free in nsTArray Length() during XSLT processing
 - CVE-2017-5438: Use-after-free in nsAutoPtr during XSLT processing
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLED, firefox-gcc5, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.2.0esr~72.5.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~52~24.3.44", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.2.0esr~72.5.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libffi4", rpm:"firefox-libffi4~5.3.1+r233831~7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~5.3.1+r233831~7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.29.5~47.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.2.0esr~72.5.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~52~24.3.44", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~52.2.0esr~72.5.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libffi4", rpm:"firefox-libffi4~5.3.1+r233831~7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~5.3.1+r233831~7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-x86", rpm:"libsoftokn3-x86~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.29.5~47.3.2", rls:"SLES11.0SP4"))) {
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
