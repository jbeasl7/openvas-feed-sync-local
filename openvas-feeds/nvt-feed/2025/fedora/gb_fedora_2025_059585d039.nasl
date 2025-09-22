# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.059585100039");
  script_cve_id("CVE-2024-54551", "CVE-2025-24208", "CVE-2025-24209", "CVE-2025-24216", "CVE-2025-24264", "CVE-2025-30427");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-059585d039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-059585d039");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-059585d039");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357987");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357990");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357993");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357998");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358000");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358002");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk' package(s) announced via the FEDORA-2025-059585d039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Limit the data stored in session state.
 * Remove the empty area below the title bar in Web Inspector when not docked.
 * Fix various crashes and rendering issues");

  script_tag(name:"affected", value:"'webkitgtk' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1", rpm:"javascriptcoregtk4.1~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-debuginfo", rpm:"javascriptcoregtk4.1-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-devel", rpm:"javascriptcoregtk4.1-devel~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-devel-debuginfo", rpm:"javascriptcoregtk4.1-devel-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0", rpm:"javascriptcoregtk6.0~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-debuginfo", rpm:"javascriptcoregtk6.0-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-devel", rpm:"javascriptcoregtk6.0-devel~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-devel-debuginfo", rpm:"javascriptcoregtk6.0-devel-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1", rpm:"webkit2gtk4.1~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-debuginfo", rpm:"webkit2gtk4.1-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-devel", rpm:"webkit2gtk4.1-devel~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-devel-debuginfo", rpm:"webkit2gtk4.1-devel-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-doc", rpm:"webkit2gtk4.1-doc~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-debugsource", rpm:"webkitgtk-debugsource~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0", rpm:"webkitgtk6.0~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-debuginfo", rpm:"webkitgtk6.0-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-devel", rpm:"webkitgtk6.0-devel~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-devel-debuginfo", rpm:"webkitgtk6.0-devel-debuginfo~2.48.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-doc", rpm:"webkitgtk6.0-doc~2.48.1~2.fc41", rls:"FC41"))) {
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
