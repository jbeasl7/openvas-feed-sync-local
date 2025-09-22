# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02531.1");
  script_cve_id("CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-8036", "CVE-2025-8037", "CVE-2025-8038", "CVE-2025-8039", "CVE-2025-8040");
  script_tag(name:"creation_date", value:"2025-07-30 04:22:58 +0000 (Wed, 30 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02531-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02531-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502531-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246664");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040939.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:02531-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

- Firefox Extended Support Release 140.1.0 ESR
 * MFSA-RESERVE-2025-1968423 (bmo#1968423)
 JavaScript engine only wrote partial return value to stack
 * MFSA-RESERVE-2025-1971581 (bmo#1971581)
 Large branch table could lead to truncated instruction
 * MFSA-RESERVE-2025-1928021 (bmo#1928021)
 CSP does not block javascript: URLs on object and embed tags
 * MFSA-RESERVE-2025-1960834 (bmo#1960834)
 DNS rebinding circumvents CORS
 * MFSA-RESERVE-2025-1964767 (bmo#1964767)
 Nameless cookies shadow secure cookies
 * MFSA-RESERVE-2025-1968414 (bmo#1968414)
 Potential user-assisted code execution in 'Copy as cURL'
 command
 * MFSA-RESERVE-2025-1971719 (bmo#1971719)
 Incorrect URL stripping in CSP reports
 * MFSA-RESERVE-2025-1974407 (bmo#1974407)
 XSLT documents could by-pass CSP
 * MFSA-RESERVE-2025-1808979 (bmo#1808979)
 CSP frame-src was not correctly enforced for paths
 * MFSA-RESERVE-2025-1970997 (bmo#1970997)
 Search terms persist in URL bar
 * MFSA-RESERVE-2025-1973990 (bmo#1973990)
 Incorrect JavaScript state machine for generators
 * MFSA-RESERVE-2025-1 (bmo#1970422, bmo#1970422, bmo#1970422,
 bmo#1970422)
 Memory safety bugs fixed in Firefox ESR 115.26, Thunderbird
 ESR 115.26, Firefox ESR 128.13, Firefox ESR 140.1,
 Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141
 * MFSA-RESERVE-2025-2 (bmo#1975058, bmo#1975058, bmo#1975998,
 bmo#1975998)
 Memory safety bugs fixed in Firefox ESR 140.1, Thunderbird
 ESR 140.1, Firefox 141 and Thunderbird 141
 * MFSA-RESERVE-2025-3 (bmo#1975961, bmo#1975961, bmo#1975961)
 Memory safety bugs fixed in Firefox ESR 128.13, Firefox ESR
 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141

Various security fixes MFSA 2025-59 (bsc#1246664):
- CVE-2025-8027: JavaScript engine only wrote partial return value to stack
- CVE-2025-8028: Large branch table could lead to truncated instruction
- CVE-2025-8029: javascript: URLs executed on object and embed tags
- CVE-2025-8036: DNS rebinding circumvents CORS
- CVE-2025-8037: Nameless cookies shadow secure cookies
- CVE-2025-8030: Potential user-assisted code execution in 'Copy as cURL' command
- CVE-2025-8031: Incorrect URL stripping in CSP reports
- CVE-2025-8032: XSLT documents could bypass CSP
- CVE-2025-8038: CSP frame-src was not correctly enforced for paths
- CVE-2025-8039: Search terms persisted in URL bar
- CVE-2025-8033: Incorrect JavaScript state machine for generators
- CVE-2025-8034: Memory safety bugs fixed in Firefox ESR 115.26, Firefox ESR 128.13, Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141
- CVE-2025-8040: Memory safety bugs fixed in Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141
- CVE-2025-8035: Memory safety bugs fixed in Firefox ESR 128.13, Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.1.0~112.273.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.1.0~112.273.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.1.0~112.273.1", rls:"SLES12.0SP5"))) {
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
