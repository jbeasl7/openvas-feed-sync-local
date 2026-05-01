# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0093");
  script_cve_id("CVE-2026-33033", "CVE-2026-33034", "CVE-2026-3902", "CVE-2026-4277", "CVE-2026-4292");
  script_tag(name:"creation_date", value:"2026-04-13 05:06:37 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0093");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0093.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35330");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/07/10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2026-0093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ASGI header spoofing via underscore/hyphen conflation. (CVE-2026-3902)
Privilege abuse in ``GenericInlineModelAdmin``. (CVE-2026-4277)
Privilege abuse in ``ModelAdmin.list_editable``. (CVE-2026-4292)
Potential denial-of-service vulnerability in ``MultiPartParser`` via
base64-encoded file upload. (CVE-2026-33033)
Potential denial-of-service vulnerability in ASGI requests via memory
upload limit bypass. (CVE-2026-33034)");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~4.1.13~1.12.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~4.1.13~1.12.mga9", rls:"MAGEIA9"))) {
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
