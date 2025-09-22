# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1449.1");
  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2728", "CVE-2015-2730", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2743", "CVE-2015-4000", "CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4495");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:23:00 +0000 (Fri, 28 Jun 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1449-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1449-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151449-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940918");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-August/001556.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nss' package(s) announced via the SUSE-SU-2015:1449-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is being updated to the current Firefox 38ESR branch (specifically the 38.2.0ESR release).

Security issues fixed:
- MFSA 2015-78 / CVE-2015-4495: Same origin violation and local file stealing via PDF reader
- MFSA 2015-79 / CVE-2015-4473/CVE-2015-4474: Miscellaneous memory safety hazards (rv:40.0 / rv:38.2)
- MFSA 2015-80 / CVE-2015-4475: Out-of-bounds read with malformed MP3 file
- MFSA 2015-82 / CVE-2015-4478: Redefinition of non-configurable JavaScript object properties
- MFSA 2015-83 / CVE-2015-4479: Overflow issues in libstagefright
- MFSA 2015-87 / CVE-2015-4484: Crash when using shared memory in JavaScript
- MFSA 2015-88 / CVE-2015-4491: Heap overflow in gdk-pixbuf when scaling bitmap images
- MFSA 2015-89 / CVE-2015-4485/CVE-2015-4486: Buffer overflows on Libvpx when decoding WebM video
- MFSA 2015-90 / CVE-2015-4487/CVE-2015-4488/CVE-2015-4489: Vulnerabilities found through code inspection
- MFSA 2015-92 / CVE-2015-4492: Use-after-free in XMLHttpRequest with shared workers

The following vulnerabilities were fixed in ESR31 and are also included here:
- CVE-2015-2724/CVE-2015-2725/CVE-2015-2726: Miscellaneous memory safety hazards (bsc#935979).
- CVE-2015-2728: Type confusion in Indexed Database Manager (bsc#935979).
- CVE-2015-2730: ECDSA signature validation fails to handle some signatures correctly (bsc#935979).
- CVE-2015-2722/CVE-2015-2733: Use-after-free in workers while using XMLHttpRequest (bsc#935979).
- CVE-2015-2734/CVE-2015-2735/CVE-2015-2736/CVE-2015-2737/CVE-2015-2738/CVE-2015-2739/CVE-2015-2740: Vulnerabilities found through code inspection (bsc#935979).
- CVE-2015-2743: Privilege escalation in PDF.js (bsc#935979).
- CVE-2015-4000: NSS accepts export-length DHE keys with regular DHE cipher suites (bsc#935033).
- CVE-2015-2721: NSS incorrectly permits skipping of ServerKeyExchange (bsc#935979).

This update also contains a lot of feature improvements and bug fixes from 31ESR to 38ESR.

Also the Mozilla NSS library switched its CKBI API from 1.98 to 2.4, which is what Firefox 38ESR uses.

Mozilla Firefox and mozilla-nss were updated to fix 17 security issues.");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.2.0esr~10.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~31.0~0.5.7.11", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.2.0esr~10.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1", rpm:"firefox-libgcc_s1~4.7.2_20130108~0.37.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~4.7.2_20130108~0.37.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.19.2.0~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.19.2.0~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.19.2.0~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.19.2.0~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.19.2.0~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.19.2.0~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.2.0esr~10.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~31.0~0.5.7.11", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.2.0esr~10.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1", rpm:"firefox-libgcc_s1~4.7.2_20130108~0.37.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~4.7.2_20130108~0.37.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.19.2.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.19.2.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.19.2.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.19.2.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.19.2.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.19.2.0~0.7.1", rls:"SLES11.0SP2"))) {
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
