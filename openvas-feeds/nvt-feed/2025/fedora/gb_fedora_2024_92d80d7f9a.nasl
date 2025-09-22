# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.92100801007102997");
  script_cve_id("CVE-2024-23271", "CVE-2024-27833", "CVE-2024-27838", "CVE-2024-27851", "CVE-2024-40857", "CVE-2024-44187");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-03 16:13:40 +0000 (Wed, 03 Jul 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-92d80d7f9a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-92d80d7f9a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-92d80d7f9a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314731");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314733");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314743");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314747");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314749");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314752");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk4.0' package(s) announced via the FEDORA-2024-92d80d7f9a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.46.1");

  script_tag(name:"affected", value:"'webkit2gtk4.0' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.0", rpm:"javascriptcoregtk4.0~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.0-debuginfo", rpm:"javascriptcoregtk4.0-debuginfo~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.0-devel", rpm:"javascriptcoregtk4.0-devel~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.0-devel-debuginfo", rpm:"javascriptcoregtk4.0-devel-debuginfo~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0", rpm:"webkit2gtk4.0~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-debuginfo", rpm:"webkit2gtk4.0-debuginfo~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-debugsource", rpm:"webkit2gtk4.0-debugsource~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-devel", rpm:"webkit2gtk4.0-devel~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-devel-debuginfo", rpm:"webkit2gtk4.0-devel-debuginfo~2.46.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-doc", rpm:"webkit2gtk4.0-doc~2.46.1~2.fc41", rls:"FC41"))) {
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
