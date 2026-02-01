# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20135.1");
  script_cve_id("CVE-2025-13878");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 15:16:05 +0000 (Wed, 21 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20135-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20135-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620135-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256997");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-January/043736.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2026:20135-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Make DNSSEC key rollovers more robust.
 * Fix a catalog zone issue, where member zones could fail to
 load.
 * Allow glue in delegations with QTYPE=ANY.
 * Fix slow speed when signing a large delegation zone with NSEC3
 opt-out.
 * Reconfiguring an NSEC3 opt-out zone to NSEC caused the zone to
 be invalid.
 * Fix a possible catalog zone issue during reconfiguration.
 * Fix the charts in the statistics channel.
 * Adding NSEC3 opt-out records could leave invalid records in
 chain.
 * Fix spurious timeouts while resolving names.
 * Fix bug where zone switches from NSEC3 to NSEC after
 retransfer.
 * AMTRELAY type 0 presentation format handling was wrong.
 * Fix parsing bug in remote-servers with key or TLS.
 * Fix DoT reconfigure/reload bug in the resolver.
 * Skip unsupported algorithms when looking for a signing key.
 * Fix dnssec-keygen key collision checking for KEY RRtype keys.
 * dnssec-verify now uses exit code 1 when failing due to illegal
 options.
 * Prevent assertion failures of dig when a server is specified
 before the -b option.
 * Skip buffer allocations if not logging.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-generic", rpm:"bind-modules-generic~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-ldap", rpm:"bind-modules-ldap~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-mysql", rpm:"bind-modules-mysql~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-perl", rpm:"bind-modules-perl~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-modules-sqlite3", rpm:"bind-modules-sqlite3~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.20.18~160000.1.1", rls:"SLES16.0.0"))) {
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
