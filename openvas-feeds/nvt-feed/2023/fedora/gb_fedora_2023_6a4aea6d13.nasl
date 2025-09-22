# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885274");
  script_cve_id("CVE-2023-44429", "CVE-2023-44446");
  script_tag(name:"creation_date", value:"2023-11-19 02:16:42 +0000 (Sun, 19 Nov 2023)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-16 19:42:53 +0000 (Mon, 16 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2023-6a4aea6d13)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6a4aea6d13");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-6a4aea6d13");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250248");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250250");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1-plugin-libav, gstreamer1-plugins-bad-free, gstreamer1-plugins-base, gstreamer1-plugins-good, gstreamer1-plugins-ugly-free, gstreamer1-rtsp-server, gstreamer1-vaapi' package(s) announced via the FEDORA-2023-6a4aea6d13 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"1.22.7");

  script_tag(name:"affected", value:"'gstreamer1-plugin-libav, gstreamer1-plugins-bad-free, gstreamer1-plugins-base, gstreamer1-plugins-good, gstreamer1-plugins-ugly-free, gstreamer1-rtsp-server, gstreamer1-vaapi' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-libav", rpm:"gstreamer1-plugin-libav~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-libav-debuginfo", rpm:"gstreamer1-plugin-libav-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-libav-debugsource", rpm:"gstreamer1-plugin-libav-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free", rpm:"gstreamer1-plugins-bad-free~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-debuginfo", rpm:"gstreamer1-plugins-bad-free-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-debugsource", rpm:"gstreamer1-plugins-bad-free-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-devel", rpm:"gstreamer1-plugins-bad-free-devel~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-extras", rpm:"gstreamer1-plugins-bad-free-extras~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-extras-debuginfo", rpm:"gstreamer1-plugins-bad-free-extras-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-fluidsynth", rpm:"gstreamer1-plugins-bad-free-fluidsynth~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-fluidsynth-debuginfo", rpm:"gstreamer1-plugins-bad-free-fluidsynth-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-libs", rpm:"gstreamer1-plugins-bad-free-libs~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-libs-debuginfo", rpm:"gstreamer1-plugins-bad-free-libs-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-opencv", rpm:"gstreamer1-plugins-bad-free-opencv~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-opencv-debuginfo", rpm:"gstreamer1-plugins-bad-free-opencv-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-wildmidi", rpm:"gstreamer1-plugins-bad-free-wildmidi~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-wildmidi-debuginfo", rpm:"gstreamer1-plugins-bad-free-wildmidi-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-zbar", rpm:"gstreamer1-plugins-bad-free-zbar~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-zbar-debuginfo", rpm:"gstreamer1-plugins-bad-free-zbar-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base", rpm:"gstreamer1-plugins-base~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base-debuginfo", rpm:"gstreamer1-plugins-base-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base-debugsource", rpm:"gstreamer1-plugins-base-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base-devel", rpm:"gstreamer1-plugins-base-devel~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base-tools", rpm:"gstreamer1-plugins-base-tools~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base-tools-debuginfo", rpm:"gstreamer1-plugins-base-tools-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good", rpm:"gstreamer1-plugins-good~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-debuginfo", rpm:"gstreamer1-plugins-good-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-debugsource", rpm:"gstreamer1-plugins-good-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-extras", rpm:"gstreamer1-plugins-good-extras~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-extras-debuginfo", rpm:"gstreamer1-plugins-good-extras-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-gtk", rpm:"gstreamer1-plugins-good-gtk~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-gtk-debuginfo", rpm:"gstreamer1-plugins-good-gtk-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-qt", rpm:"gstreamer1-plugins-good-qt~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-qt-debuginfo", rpm:"gstreamer1-plugins-good-qt-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-qt6", rpm:"gstreamer1-plugins-good-qt6~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good-qt6-debuginfo", rpm:"gstreamer1-plugins-good-qt6-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-ugly-free", rpm:"gstreamer1-plugins-ugly-free~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-ugly-free-debuginfo", rpm:"gstreamer1-plugins-ugly-free-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-ugly-free-debugsource", rpm:"gstreamer1-plugins-ugly-free-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-rtsp-server", rpm:"gstreamer1-rtsp-server~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-rtsp-server-debuginfo", rpm:"gstreamer1-rtsp-server-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-rtsp-server-debugsource", rpm:"gstreamer1-rtsp-server-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-rtsp-server-devel", rpm:"gstreamer1-rtsp-server-devel~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-rtsp-server-devel-debuginfo", rpm:"gstreamer1-rtsp-server-devel-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-vaapi", rpm:"gstreamer1-vaapi~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-vaapi-debuginfo", rpm:"gstreamer1-vaapi-debuginfo~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-vaapi-debugsource", rpm:"gstreamer1-vaapi-debugsource~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-vaapi-devel", rpm:"gstreamer1-vaapi-devel~1.22.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-vaapi-devel-docs", rpm:"gstreamer1-vaapi-devel-docs~1.22.7~1.fc39", rls:"FC39"))) {
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
