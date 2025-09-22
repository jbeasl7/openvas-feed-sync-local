# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0342");
  script_cve_id("CVE-2024-0760", "CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");
  script_tag(name:"creation_date", value:"2024-11-04 04:11:34 +0000 (Mon, 04 Nov 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 15:15:05 +0000 (Tue, 23 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0342");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0342.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33437");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6909-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/23/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the MGASA-2024-0342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A malicious client can send many DNS messages over TCP, potentially
causing the server to become unstable while the attack is in progress.
The server may recover after the attack ceases. Use of ACLs will not
mitigate the attack. (CVE-2024-0760)
Resolver caches and authoritative zone databases that hold significant
numbers of RRs for the same hostname (of any RTYPE) can suffer from
degraded performance as content is being added or updated, and also when
handling client queries for this name. (CVE-2024-1737)
If a server hosts a zone containing a 'KEY' Resource Record, or a
resolver DNSSEC-validates a 'KEY' Resource Record from a DNSSEC-signed
domain in cache, a client can exhaust resolver CPU resources by sending
a stream of SIG(0) signed requests. (CVE-2024-1975)
Client queries that trigger serving stale data and that also require
lookups in local authoritative zone data may result in an assertion
failure. (CVE-2024-4076)");

  script_tag(name:"affected", value:"'bind' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-filesystem", rpm:"bind-dlz-filesystem~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-ldap", rpm:"bind-dlz-ldap~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-mysql", rpm:"bind-dlz-mysql~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dlz-sqlite3", rpm:"bind-dlz-sqlite3~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bind9.18.28", rpm:"lib64bind9.18.28~9.18.28~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9.18.28", rpm:"libbind9.18.28~9.18.28~1.mga9", rls:"MAGEIA9"))) {
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
