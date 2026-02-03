# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.100897998797999");
  script_cve_id("CVE-2025-13878");
  script_tag(name:"creation_date", value:"2026-02-02 04:44:26 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 15:16:05 +0000 (Wed, 21 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-d8979b7a9c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-d8979b7a9c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-d8979b7a9c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2415843");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.21.17/doc/arm/html/notes.html#notes-for-bind-9-21-17");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9-next' package(s) announced via the FEDORA-2026-d8979b7a9c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 9.21.17 (rhbz#2415843)

## Security Fixes:

- Fix incorrect length checks for BRID and HHIT records. (CVE-2025-13878)

## New Features:

- Add support for Extended DNS Error 9 (Missing DNSKEY).
- Add support for Extended DNS Error 13 (Cached Error).
- Add support for Generalized DNS Notifications.

# Features Changes:

- Add more information to the rndc recursing output about fetches.
- Enforce bounds of multiple configuration options.

## Bug Fixes:

- Fix inbound IXFR performance regression.
- Make DNSSEC key rollovers more robust.
- Fix a catalog zone issue, where member zones could fail to load.
- Fix slow speed when signing a large delegation zone with NSEC3 opt-out.
- Reconfiguring an NSEC3 opt-out zone to NSEC caused the zone to be invalid.
- Fix a possible catalog zone issue during reconfiguration.
- Fix the charts in the statistics channel.

[link moved to references]");

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

  if(!isnull(res = isrpmvuln(pkg:"bind9-next", rpm:"bind9-next~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-chroot", rpm:"bind9-next-chroot~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debuginfo", rpm:"bind9-next-debuginfo~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debugsource", rpm:"bind9-next-debugsource~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils", rpm:"bind9-next-dnssec-utils~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils-debuginfo", rpm:"bind9-next-dnssec-utils-debuginfo~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-doc", rpm:"bind9-next-doc~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs", rpm:"bind9-next-libs~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs-debuginfo", rpm:"bind9-next-libs-debuginfo~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils", rpm:"bind9-next-utils~9.21.17~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils-debuginfo", rpm:"bind9-next-utils-debuginfo~9.21.17~2.fc42", rls:"FC42"))) {
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
