# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0023");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087", "CVE-2025-14512", "CVE-2025-3360", "CVE-2025-7039", "CVE-2026-0988");
  script_tag(name:"creation_date", value:"2026-01-29 04:35:50 +0000 (Thu, 29 Jan 2026)");
  script_version("2026-01-29T08:35:42+0000");
  script_tag(name:"last_modification", value:"2026-01-29 08:35:42 +0000 (Thu, 29 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 15:15:51 +0000 (Wed, 26 Nov 2025)");

  script_name("Mageia: Security Advisory (MGASA-2026-0023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0023");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0023.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35052");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7971-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the MGASA-2026-0023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Glib prior to 2.82.5 is vulnerable to integer overflow and buffer
under-read when parsing a very long invalid iso 8601 timestamp with
g_date_time_new_from_iso8601(). (CVE-2025-3360)
Buffer under-read on glib through glib/gfileutils.c via get_tmp_file().
(CVE-2025-7039)
Integer overflow in in g_escape_uri_string(). (CVE-2025-13601)
Buffer underflow in gvariant parser leads to heap corruption.
(CVE-2025-14087)
Integer overflow in glib gio attribute escaping causes heap buffer
overflow. (CVE-2025-14512)
Denial of service via integer overflow in
g_buffered_input_stream_peek(). (CVE-2026-0988)");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0", rpm:"glib2.0~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2.0-tests", rpm:"glib2.0-tests~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0-static-devel", rpm:"lib64glib2.0-static-devel~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0-static-devel", rpm:"libglib2.0-static-devel~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.76.3~1.6.mga9", rls:"MAGEIA9"))) {
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
