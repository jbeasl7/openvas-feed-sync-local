# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887308");
  script_cve_id("CVE-2024-0760", "CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");
  script_tag(name:"creation_date", value:"2024-08-06 07:33:57 +0000 (Tue, 06 Aug 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 15:15:05 +0000 (Tue, 23 Jul 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8af1780fdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8af1780fdf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8af1780fdf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299467");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300837");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.18.28/doc/arm/html/notes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind, bind-dyndb-ldap' package(s) announced via the FEDORA-2024-8af1780fdf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to BIND 9.18.28


## Security Fixes

- A malicious DNS client that sent many queries over TCP but never read the responses could cause a server to respond slowly or not at all for other clients. This has been fixed. (CVE-2024-0760) [GL #4481]

- It is possible to craft excessively large resource records sets, which have the effect of slowing down database processing. This has been addressed by adding a configurable limit to the number of records that can be stored per name and type in a cache or zone database. The default is 100, which can be tuned with the new max-records-per-type option. [GL #497] [GL #3405]

 It is possible to craft excessively large numbers of resource record types for a given owner name, which has the effect of slowing down database processing. This has been addressed by adding a configurable limit to the number of records that can be stored per name and type in a cache or zone database. The default is 100, which can be tuned with the new max-types-per-name option. (CVE-2024-1737) [GL #3403]

 ISC would like to thank Toshifumi Sakaguchi who independently discovered and responsibly reported the issue to ISC. [GL #4548]

- Validating DNS messages signed using the SIG(0) protocol (RFC 2931) could cause excessive CPU load, leading to a denial-of-service condition. Support for SIG(0) message validation was removed from this version of named. (CVE-2024-1975) [GL #4480]

- Due to a logic error, lookups that triggered serving stale data and required lookups in local authoritative zone data could have resulted in an assertion failure. This has been fixed. (CVE-2024-4076) [GL #4507]

Potential data races were found in our DoH implementation, related to HTTP/2 session object management and endpoints set object management after reconfiguration. These issues have been fixed. [GL #4473]

ISC would like to thank Dzintars and Ivo from nic.lv for bringing this to our attention.

- When looking up the NS records of parent zones as part of looking up DS records, it was possible for named to trigger an assertion failure if serve-stale was enabled. This has been fixed. [GL #4661]

- Source: [link moved to references]");

  script_tag(name:"affected", value:"'bind, bind-dyndb-ldap' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-filesystem", rpm:"bind-dlz-filesystem~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-filesystem-debuginfo", rpm:"bind-dlz-filesystem-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-ldap", rpm:"bind-dlz-ldap~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-ldap-debuginfo", rpm:"bind-dlz-ldap-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-mysql", rpm:"bind-dlz-mysql~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-mysql-debuginfo", rpm:"bind-dlz-mysql-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-sqlite3", rpm:"bind-dlz-sqlite3~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-sqlite3-debuginfo", rpm:"bind-dlz-sqlite3-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils-debuginfo", rpm:"bind-dnssec-utils-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap", rpm:"bind-dyndb-ldap~11.10~29.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap-debuginfo", rpm:"bind-dyndb-ldap-debuginfo~11.10~29.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dyndb-ldap-debugsource", rpm:"bind-dyndb-ldap-debugsource~11.10~29.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.18.28~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.18.28~2.fc40", rls:"FC40"))) {
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
