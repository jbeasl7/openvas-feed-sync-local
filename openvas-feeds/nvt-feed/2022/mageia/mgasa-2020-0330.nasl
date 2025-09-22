# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0330");
  script_cve_id("CVE-2020-12100", "CVE-2020-12673", "CVE-2020-12674");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-17 14:26:58 +0000 (Mon, 17 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0330");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0330.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27099");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2020-August/000441.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2020-August/000442.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2020-August/000443.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the MGASA-2020-0330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-12100: Receiving mail with deeply nested MIME parts leads to resource
exhaustion as Dovecot attempts to parse it.
CVE-2020-12673: Dovecot's NTLM implementation does not correctly check message
buffer size, which leads to reading past allocation which can lead to crash.
CVE-2020-12674: Dovecot's RPA mechanism implementation accepts zero-length
message, which leads to assert-crash later on.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole-devel", rpm:"dovecot-pigeonhole-devel~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-mysql", rpm:"dovecot-plugins-mysql~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-pgsql", rpm:"dovecot-plugins-pgsql~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-sqlite", rpm:"dovecot-plugins-sqlite~2.3.11.3~1.mga7", rls:"MAGEIA7"))) {
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
