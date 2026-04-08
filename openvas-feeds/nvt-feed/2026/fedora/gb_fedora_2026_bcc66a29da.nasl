# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.98999966972910097");
  script_cve_id("CVE-2026-1519", "CVE-2026-3104", "CVE-2026-3119", "CVE-2026-3591");
  script_tag(name:"creation_date", value:"2026-04-06 04:59:34 +0000 (Mon, 06 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 14:16:36 +0000 (Wed, 25 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-bcc66a29da)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-bcc66a29da");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-bcc66a29da");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2440560");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2451573");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.21.20/doc/arm/html/notes.html#notes-for-bind-9-21-20");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2026-1519");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2026-3104");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2026-3119");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2026-3591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9-next' package(s) announced via the FEDORA-2026-bcc66a29da advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 9.21.20 (rhbz#2440560)

## Security Fixes:

- Fix unbounded NSEC3 iterations when validating referrals to unsigned delegations. ([CVE-2026-1519]([link moved to references]))
- Fix memory leaks in code preparing DNSSEC proofs of non-existence. ([CVE-2026-3104]([link moved to references]))
- Prevent a crash in code processing queries containing a TKEY record. ([CVE-2026-3119]([link moved to references]))
- Fix a stack use-after-return flaw in SIG(0) handling code. ([CVE-2026-3591]([link moved to references]))

## New Features:

- Provide response round-trip time (RTT) counters via statistics channel.
- Introduce max-delegation-servers configuration option.

## Bug Fixes:

- Fix parsing key inactivation time in KASP code.
- Fix the handling of key statements defined inside views.

# Update to 9.21.19

## Security Fixes:

- Fix a use-after-free error in dns_client_resolve() triggered by a DNAME response.
- Fix a NULL pointer dereference in qp-trie cache code.
- Immediately remove purged ADB names and entries from the SIEVE list.

## Feature Changes:

- Record query time for all dnstap responses.
- Optimize TCP source port selection on Linux.

and multiple bug fixes.

# Update to 9.21.18

## Feature Changes:

- Enable minimal ANY answers by default.
- Lowercase the NSEC Next Domain Name field.
- Update requirements for system test suite.

## Bug Fixes:

- Make catalog zone names and member zones' entry names case-insensitive. [GL #5693]
- Fix implementation of BRID and HHIT record types. [GL #5710]
- Fix implementation of DSYNC record type. [GL #5711]
- Fix response policy and catalog zones to work with $INCLUDE directive.

Source: [link moved to references]");

  script_tag(name:"affected", value:"'bind9-next' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"bind9-next", rpm:"bind9-next~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-chroot", rpm:"bind9-next-chroot~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debuginfo", rpm:"bind9-next-debuginfo~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debugsource", rpm:"bind9-next-debugsource~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils", rpm:"bind9-next-dnssec-utils~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils-debuginfo", rpm:"bind9-next-dnssec-utils-debuginfo~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-doc", rpm:"bind9-next-doc~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs", rpm:"bind9-next-libs~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs-debuginfo", rpm:"bind9-next-libs-debuginfo~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils", rpm:"bind9-next-utils~9.21.20~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils-debuginfo", rpm:"bind9-next-utils-debuginfo~9.21.20~1.fc42", rls:"FC42"))) {
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
