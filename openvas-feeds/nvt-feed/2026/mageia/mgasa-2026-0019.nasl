# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0019");
  script_tag(name:"creation_date", value:"2026-01-28 04:24:03 +0000 (Wed, 28 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0019");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0019.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35064");
  script_xref(name:"URL", value:"https://www.haproxy.org/download/2.8/src/CHANGELOG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy' package(s) announced via the MGASA-2026-0019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Haproxy has two major, a few medium and a few minor bugs fixed in the last
upstream version 2.8.18 of branch 2.8.

Fixed major bugs list:
- quic: use ncbmbuf for CRYPTO handling
- stream: Force channel analysis on successful synchronous send

Fixed medium bugs list:
- dns: bind the nameserver sockets to the initiating thread
- h1: prevent a crash on HTTP/2 upgrade
- h3: do not overwrite interim with final response
- h3: handle interim response properly on FE side
- h3: properly encode response after interim one in same buf
- http-ana: Don't close server connection on read0 in TUNNEL mode
- mux-quic: adjust wakeup behavior
- mux-quic: ensure Early-data header is set
- quic: CRYPTO frame freeing without eb_delete()
- resolvers: make the process_resolvers() task single-threaded
- ssl: Crash because of dangling ckch_store reference in a ckch instance
- ssl: take care of second client hello
- stick-tables: Always return the good stksess from stktable_set_entry
- stick-tables: Don't forget to dec count on failure.");

  script_tag(name:"affected", value:"'haproxy' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.8.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-noquic", rpm:"haproxy-noquic~2.8.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-quic", rpm:"haproxy-quic~2.8.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-utils", rpm:"haproxy-utils~2.8.18~1.mga9", rls:"MAGEIA9"))) {
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
