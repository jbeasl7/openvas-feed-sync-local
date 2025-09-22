# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10010097126101397");
  script_cve_id("CVE-2025-47183", "CVE-2025-47219", "CVE-2025-47806", "CVE-2025-47807", "CVE-2025-47808");
  script_tag(name:"creation_date", value:"2025-08-20 15:25:15 +0000 (Wed, 20 Aug 2025)");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 14:15:28 +0000 (Tue, 12 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-dd97126e3a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-dd97126e3a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-dd97126e3a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387232");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387235");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) announced via the FEDORA-2025-dd97126e3a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.26.3.");

  script_tag(name:"affected", value:"'mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1", rpm:"mingw-gstreamer1~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-bad-free", rpm:"mingw-gstreamer1-plugins-bad-free~1.26.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-base", rpm:"mingw-gstreamer1-plugins-base~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-good", rpm:"mingw-gstreamer1-plugins-good~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1", rpm:"mingw32-gstreamer1~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-debuginfo", rpm:"mingw32-gstreamer1-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free", rpm:"mingw32-gstreamer1-plugins-bad-free~1.26.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw32-gstreamer1-plugins-bad-free-debuginfo~1.26.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base", rpm:"mingw32-gstreamer1-plugins-base~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base-debuginfo", rpm:"mingw32-gstreamer1-plugins-base-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good", rpm:"mingw32-gstreamer1-plugins-good~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good-debuginfo", rpm:"mingw32-gstreamer1-plugins-good-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1", rpm:"mingw64-gstreamer1~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-debuginfo", rpm:"mingw64-gstreamer1-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free", rpm:"mingw64-gstreamer1-plugins-bad-free~1.26.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw64-gstreamer1-plugins-bad-free-debuginfo~1.26.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base", rpm:"mingw64-gstreamer1-plugins-base~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base-debuginfo", rpm:"mingw64-gstreamer1-plugins-base-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good", rpm:"mingw64-gstreamer1-plugins-good~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good-debuginfo", rpm:"mingw64-gstreamer1-plugins-good-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
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
