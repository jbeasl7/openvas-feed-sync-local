# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1978.1");
  script_cve_id("CVE-2015-4513", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-11-05 15:41:35 +0000 (Thu, 05 Nov 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1978-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1978-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151978-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952810");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-November/001675.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2015:1978-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Mozilla Firefox, NSS and NSPR update fixes the following security and non security issues.

- mozilla-nspr was updated to version 4.10.10 (bsc#952810)
 * MFSA 2015-133/CVE-2015-7183
 (bmo#1205157)
 NSPR memory corruption issues

- mozilla-nss was updated to 3.19.2.1 (bsc#952810)
 * MFSA 2015-133/CVE-2015-7181/CVE-2015-7182
 (bmo#1192028, bmo#1202868)
 NSS and NSPR memory corruption issues

- MozillaFirefox was updated to 38.4.0 ESR (bsc#952810)
 * MFSA 2015-116/CVE-2015-4513
 (bmo#1107011, bmo#1191942, bmo#1193038, bmo#1204580,
 bmo#1204669, bmo#1204700, bmo#1205707, bmo#1206564,
 bmo#1208665, bmo#1209471, bmo#1213979)
 Miscellaneous memory safety hazards (rv:42.0 / rv:38.4)
 * MFSA 2015-122/CVE-2015-7188
 (bmo#1199430)
 Trailing whitespace in IP address hostnames can bypass
 same-origin policy
 * MFSA 2015-123/CVE-2015-7189
 (bmo#1205900)
 Buffer overflow during image interactions in canvas
 * MFSA 2015-127/CVE-2015-7193
 (bmo#1210302)
 CORS preflight is bypassed when non-standard Content-Type
 headers are received
 * MFSA 2015-128/CVE-2015-7194
 (bmo#1211262)
 Memory corruption in libjar through zip files
 * MFSA 2015-130/CVE-2015-7196
 (bmo#1140616)
 JavaScript garbage collection crash with Java applet
 * MFSA 2015-131/CVE-2015-7198/CVE-2015-7199/CVE-2015-7200
 (bmo#1204061, bmo#1188010, bmo#1204155)
 Vulnerabilities found through code inspection
 * MFSA 2015-132/CVE-2015-7197
 (bmo#1204269)
 Mixed content WebSocket policy bypass through workers
 * MFSA 2015-133/CVE-2015-7181/CVE-2015-7182/CVE-2015-7183
 (bmo#1202868, bmo#1192028, bmo#1205157)
 NSS and NSPR memory corruption issues
- fix printing on landscape media (bsc#908275)");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.4.0esr~25.3", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~38~12.19", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.4.0esr~25.3", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.19.2.1~12.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.19.2.1~12.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.10~16.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.10~16.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.10.10~16.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.19.2.1~12.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.19.2.1~12.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.19.2.1~12.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.19.2.1~12.1", rls:"SLES11.0SP2"))) {
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
