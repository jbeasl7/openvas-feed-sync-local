# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1414.1");
  script_cve_id("CVE-2025-2817");
  script_tag(name:"creation_date", value:"2025-05-01 04:10:38 +0000 (Thu, 01 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1414-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251414-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241621");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039109.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:1414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

- Firefox Extended Support Release 128.10.0 ESR MFSA 2025-29 (bsc#1241621):
 * CVE-2025-2817: Potential privilege escalation in Firefox Updater
 * MFSA-RESERVE-2025-193709: WebGL shader attribute memory corruption in Firefox for macOS
 * MFSA-RESERVE-2025-1958350: Process isolation bypass using `javascript:` URI links in
 cross-origin frames
 * MFSA-RESERVE-2025-1949994: Potential local code execution in 'copy as cURL' command
 * MFSA-RESERVE-2025-1952465: Unsafe attribute access during XPath parsing
 * MFSA-RESERVE-2025-3: Memory safety bugs fixed in Firefox 138, Thunderbird 138,
 Firefox ESR 128.10, and Thunderbird 128.10
 * MFSA-RESERVE-2025-7: Memory safety bug fixed in Firefox ESR 128.10 and Thunderbird
 128.10");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.10.0~112.255.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.10.0~112.255.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.10.0~112.255.1", rls:"SLES12.0SP5"))) {
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
