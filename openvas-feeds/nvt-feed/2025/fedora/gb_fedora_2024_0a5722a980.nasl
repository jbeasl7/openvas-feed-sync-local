# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.097572297980");
  script_cve_id("CVE-2024-47537", "CVE-2024-47538", "CVE-2024-47539", "CVE-2024-47540", "CVE-2024-47541", "CVE-2024-47542", "CVE-2024-47543", "CVE-2024-47600", "CVE-2024-47606", "CVE-2024-47607", "CVE-2024-47615", "CVE-2024-47774", "CVE-2024-47775", "CVE-2024-47777", "CVE-2024-47778", "CVE-2024-47835");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:57:16 +0000 (Wed, 18 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-0a5722a980)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-0a5722a980");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-0a5722a980");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331794");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331798");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331815");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331819");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331829");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331865");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331875");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331890");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331894");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331899");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331903");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331907");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332091");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332093");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332096");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332098");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-directxmath, mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) announced via the FEDORA-2024-0a5722a980 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to gstreamer-1.24.10, fixes multiple CVEs.");

  script_tag(name:"affected", value:"'mingw-directxmath, mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-directxmath", rpm:"mingw-directxmath~3.20~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1", rpm:"mingw-gstreamer1~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-bad-free", rpm:"mingw-gstreamer1-plugins-bad-free~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-base", rpm:"mingw-gstreamer1-plugins-base~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-good", rpm:"mingw-gstreamer1-plugins-good~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-directxmath", rpm:"mingw32-directxmath~3.20~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1", rpm:"mingw32-gstreamer1~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-debuginfo", rpm:"mingw32-gstreamer1-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free", rpm:"mingw32-gstreamer1-plugins-bad-free~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw32-gstreamer1-plugins-bad-free-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base", rpm:"mingw32-gstreamer1-plugins-base~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base-debuginfo", rpm:"mingw32-gstreamer1-plugins-base-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good", rpm:"mingw32-gstreamer1-plugins-good~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good-debuginfo", rpm:"mingw32-gstreamer1-plugins-good-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-directxmath", rpm:"mingw64-directxmath~3.20~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1", rpm:"mingw64-gstreamer1~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-debuginfo", rpm:"mingw64-gstreamer1-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free", rpm:"mingw64-gstreamer1-plugins-bad-free~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw64-gstreamer1-plugins-bad-free-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base", rpm:"mingw64-gstreamer1-plugins-base~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base-debuginfo", rpm:"mingw64-gstreamer1-plugins-base-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good", rpm:"mingw64-gstreamer1-plugins-good~1.24.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good-debuginfo", rpm:"mingw64-gstreamer1-plugins-good-debuginfo~1.24.10~1.fc41", rls:"FC41"))) {
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
