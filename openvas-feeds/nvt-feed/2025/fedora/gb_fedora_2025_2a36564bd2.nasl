# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.29736564981002");
  script_cve_id("CVE-2025-3887");
  script_tag(name:"creation_date", value:"2025-06-02 04:11:15 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-06-02T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-2a36564bd2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-2a36564bd2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-2a36564bd2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367919");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367930");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1-plugins-bad-free' package(s) announced via the FEDORA-2025-2a36564bd2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"backport fix for CVE-2025-3887 (resolves rhbz#2367919)");

  script_tag(name:"affected", value:"'gstreamer1-plugins-bad-free' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-openh264", rpm:"gstreamer1-plugin-openh264~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-openh264-debuginfo", rpm:"gstreamer1-plugin-openh264-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free", rpm:"gstreamer1-plugins-bad-free~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-debuginfo", rpm:"gstreamer1-plugins-bad-free-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-debugsource", rpm:"gstreamer1-plugins-bad-free-debugsource~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-devel", rpm:"gstreamer1-plugins-bad-free-devel~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-extras", rpm:"gstreamer1-plugins-bad-free-extras~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-extras-debuginfo", rpm:"gstreamer1-plugins-bad-free-extras-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-fluidsynth", rpm:"gstreamer1-plugins-bad-free-fluidsynth~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-fluidsynth-debuginfo", rpm:"gstreamer1-plugins-bad-free-fluidsynth-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-libs", rpm:"gstreamer1-plugins-bad-free-libs~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-libs-debuginfo", rpm:"gstreamer1-plugins-bad-free-libs-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-opencv", rpm:"gstreamer1-plugins-bad-free-opencv~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-opencv-debuginfo", rpm:"gstreamer1-plugins-bad-free-opencv-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-wildmidi", rpm:"gstreamer1-plugins-bad-free-wildmidi~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-wildmidi-debuginfo", rpm:"gstreamer1-plugins-bad-free-wildmidi-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-zbar", rpm:"gstreamer1-plugins-bad-free-zbar~1.24.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-zbar-debuginfo", rpm:"gstreamer1-plugins-bad-free-zbar-debuginfo~1.24.11~2.fc41", rls:"FC41"))) {
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
