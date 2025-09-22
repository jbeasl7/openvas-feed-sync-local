# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3105.1");
  script_cve_id("CVE-2016-5285", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9074", "CVE-2016-9079");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 12:53:51 +0000 (Mon, 30 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3105-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163105-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992549");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002474.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nss' package(s) announced via the SUSE-SU-2016:3105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, mozilla-nss fixes security issues and bugs.

The following vulnerabilities were fixed in Firefox ESR 45.5.1 (bsc#1009026):

- CVE-2016-9079: Use-after-free in SVG Animation (bsc#1012964 MFSA 2016-92)
- CVE-2016-5297: Incorrect argument length checking in Javascript (bsc#1010401)
- CVE-2016-9066: Integer overflow leading to a buffer overflow in nsScriptLoadHandler (bsc#1010404)
- CVE-2016-5296: Heap-buffer-overflow WRITE in rasterize_edges_1 (bsc#1010395)
- CVE-2016-9064: Addons update must verify IDs match between current and new versions (bsc#1010402)
- CVE-2016-5290: Memory safety bugs fixed in Firefox 50 and Firefox ESR 45.5 (bsc#1010427)
- CVE-2016-5291: Same-origin policy violation using local HTML file and saved shortcut file (bsc#1010410)

The following vulnerabilities were fixed in mozilla-nss 3.21.3:

- CVE-2016-9074: Insufficient timing side-channel resistance in divSpoiler (bsc#1010422)
- CVE-2016-5285: Missing NULL check in PK11_SignWithSymKey / ssl3_ComputeRecordMACConstantTime causes server crash (bsc#1010517)

The following bugs were fixed:

- Firefox would fail to go into fullscreen mode with some window managers (bsc#992549)
- font warning messages would flood console, now using fontconfig configuration from
 firefox-fontconfig instead of the system one (bsc#1000751)");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.5.1esr~63.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.5.1esr~63.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.21.3~30.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.21.3~30.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.21.3~30.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.21.3~30.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.21.3~30.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.21.3~30.1", rls:"SLES11.0SP2"))) {
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
