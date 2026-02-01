# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20085.1");
  script_cve_id("CVE-2025-40778", "CVE-2025-40780", "CVE-2025-8677");
  script_tag(name:"creation_date", value:"2026-01-22 04:25:52 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-22 16:15:42 +0000 (Wed, 22 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20085-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620085-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252380");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023814.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2026:20085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security Fixes:
 * CVE-2025-40778: Fixed cache poisoning attacks with unsolicited RRs (bsc#1252379)
 * CVE-2025-40780: Fixed cache poisoning due to weak PRNG (bsc#1252380)
 * CVE-2025-8677: Fixed resource exhaustion via malformed DNSKEY handling (bsc#1252378)

 New Features:
 * Add dnssec-policy keys configuration check to named-checkconf.
 * Add a new option `manual-mode` to dnssec-policy.
 * Add a new option `servfail-until-ready` to response-policy
 zones.
 * Support for parsing HHIT and BRID records has been added.
 * Support for parsing DSYNC records has been added.

 Removed Features:
 * Deprecate the `tkey-gssapi-credential` statement.
 * Obsolete the `tkey-domain` statement.

 Feature Changes:
 * Add deprecation warnings for RSASHA1, RSASHA1-NSEC3SHA1, and DS
 digest type 1.

 Bug Fixes:
 * Missing DNSSEC information when CD bit is set in query.
 * rndc sign during ZSK rollover will now replace signatures.
 * Use signer name when disabling DNSSEC algorithms.
 * Preserve cache when reload fails and reload the server again.
 * Prevent spurious SERVFAILs for certain 0-TTL resource records.
 * Fix unexpected termination if catalog-zones had undefined
 `default-primaries`.
 * Stale RRsets in a CNAME chain were not always refreshed.
 * Add RPZ extended DNS error for zones with a CNAME override
 policy configured.
 * Fix dig +keepopen option.
 * Log dropped or slipped responses in the query-errors category.
 * Fix synth-from-dnssec not working in some scenarios.
 * Clean enough memory when adding new ADB names/entries under
 memory pressure.
 * Prevent spurious validation failures.
 * Ensure file descriptors 0-2 are in use before using libuv
 [bsc#1230649]");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-generic", rpm:"bind-modules-generic~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-ldap", rpm:"bind-modules-ldap~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-mysql", rpm:"bind-modules-mysql~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-perl", rpm:"bind-modules-perl~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-sqlite3", rpm:"bind-modules-sqlite3~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.20.15~160000.1.1", rls:"SLES16.0.0"))) {
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
