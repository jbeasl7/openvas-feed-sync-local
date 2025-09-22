# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0224");
  script_cve_id("CVE-2023-52076");
  script_tag(name:"creation_date", value:"2024-06-17 04:12:21 +0000 (Mon, 17 Jun 2024)");
  script_version("2024-06-17T08:31:36+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:36 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 17:14:24 +0000 (Fri, 02 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0224)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0224");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0224.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33282");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6808-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'atril' package(s) announced via the MGASA-2024-0224 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Atril Document Viewer is the default document reader of the MATE desktop
environment for Linux. A path traversal and arbitrary file write
vulnerability exists in versions of Atril prior to 1.26.2. This
vulnerability is capable of writing arbitrary files anywhere on the
filesystem to which the user opening a crafted document has access. The
only limitation is that this vulnerability cannot be exploited to
overwrite existing files, but that doesn't stop an attacker from
achieving Remote Command Execution on the target system.
(CVE-2023-52076)");

  script_tag(name:"affected", value:"'atril' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"atril", rpm:"atril~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atril-dvi", rpm:"atril-dvi~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64atril-devel", rpm:"lib64atril-devel~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64atril-gir1.5.0", rpm:"lib64atril-gir1.5.0~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64atril3", rpm:"lib64atril3~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatril-devel", rpm:"libatril-devel~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatril-gir1.5.0", rpm:"libatril-gir1.5.0~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatril3", rpm:"libatril3~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
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
