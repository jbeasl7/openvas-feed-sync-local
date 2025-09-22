# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9879998891001001003");
  script_cve_id("CVE-2025-8010", "CVE-2025-8011", "CVE-2025-8576", "CVE-2025-8578", "CVE-2025-8579", "CVE-2025-8580", "CVE-2025-8581", "CVE-2025-8582", "CVE-2025-8583", "CVE-2025-8879", "CVE-2025-8880", "CVE-2025-8881", "CVE-2025-8882", "CVE-2025-8901");
  script_tag(name:"creation_date", value:"2025-09-01 04:10:44 +0000 (Mon, 01 Sep 2025)");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-b7cb89ddd3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b7cb89ddd3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b7cb89ddd3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389708");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2025-b7cb89ddd3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- * CVE-2025-8010: Type Confusion in V8
- * CVE-2025-8011: Type Confusion in V8
- * CVE-2025-8576: Use after free in Extensions
- * CVE-2025-8578: Use after free in Cast
- * CVE-2025-8579: Inappropriate implementation in Gemini Live in Chrome
- * CVE-2025-8580: Inappropriate implementation in Filesystems
- * CVE-2025-8581: Inappropriate implementation in Extensions
- * CVE-2025-8582: Insufficient validation of untrusted input in DOM
- * CVE-2025-8583: Inappropriate implementation in Permissions
- * CVE-2025-8879: Heap buffer overflow in libaom
- * CVE-2025-8880: Race in V8
- * CVE-2025-8901: Out of bounds write in ANGLE
- * CVE-2025-8881: Inappropriate implementation in File Picker
- * CVE-2025-8882: Use after free in Aura");

  script_tag(name:"affected", value:"'cef' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~139.0.26^chromium139.0.7258.127~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~139.0.26^chromium139.0.7258.127~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~139.0.26^chromium139.0.7258.127~1.fc42", rls:"FC42"))) {
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
