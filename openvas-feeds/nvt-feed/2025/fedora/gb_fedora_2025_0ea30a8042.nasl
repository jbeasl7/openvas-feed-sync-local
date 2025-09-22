# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.01019730978042");
  script_cve_id("CVE-2025-8578", "CVE-2025-8579", "CVE-2025-8581", "CVE-2025-8879", "CVE-2025-8880", "CVE-2025-8881", "CVE-2025-8882", "CVE-2025-8901");
  script_tag(name:"creation_date", value:"2025-08-18 04:17:14 +0000 (Mon, 18 Aug 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-0ea30a8042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-0ea30a8042");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-0ea30a8042");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387036");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387037");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387038");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387039");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387040");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387041");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387446");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388155");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388156");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388157");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388159");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388160");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388161");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388162");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388164");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-0ea30a8042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated to 139.0.7258.127

 * CVE-2025-8879: Heap buffer overflow in libaom
 * CVE-2025-8880: Race in V8
 * CVE-2025-8901: Out of bounds write in ANGLE
 * CVE-2025-8881: Inappropriate implementation in File Picker
 * CVE-2025-8882: Use after free in Aura
 * Fix FTBFS with rust-1.89.0");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~139.0.7258.127~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~139.0.7258.127~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~139.0.7258.127~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~139.0.7258.127~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~139.0.7258.127~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~139.0.7258.127~1.fc41", rls:"FC41"))) {
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
