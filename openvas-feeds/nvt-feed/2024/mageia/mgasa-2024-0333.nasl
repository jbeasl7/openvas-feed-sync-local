# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0333");
  script_cve_id("CVE-2024-8508");
  script_tag(name:"creation_date", value:"2024-10-16 04:11:13 +0000 (Wed, 16 Oct 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-17 19:28:03 +0000 (Tue, 17 Dec 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0333");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0333.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33621");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound' package(s) announced via the MGASA-2024-0333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NLnet Labs Unbound up to and including version 1.21.0 contains a
vulnerability when handling replies with very large RRsets that it needs
to perform name compression for. Malicious upstreams responses with very
large RRsets can cause Unbound to spend a considerable time applying
name compression to downstream replies. This can lead to degraded
performance and eventually denial of service in well orchestrated
attacks. The vulnerability can be exploited by a malicious actor
querying Unbound for the specially crafted contents of a malicious zone
with very large RRsets. Before Unbound replies to the query it will try
to apply name compression which was an unbounded operation that could
lock the CPU until the whole packet was complete. Unbound version 1.21.1
introduces a hard limit on the number of name compression calculations
it is willing to do per packet. Packets that need more compression will
result in semi-compressed packets or truncated packets, even on TCP for
huge messages, to avoid locking the CPU for long. This change should not
affect normal DNS traffic.");

  script_tag(name:"affected", value:"'unbound' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64unbound-devel", rpm:"lib64unbound-devel~1.21.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64unbound8", rpm:"lib64unbound8~1.21.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunbound-devel", rpm:"libunbound-devel~1.21.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunbound8", rpm:"libunbound8~1.21.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.21.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.21.1~1.mga9", rls:"MAGEIA9"))) {
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
