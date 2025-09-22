# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886294");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:33 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-e34efa1300)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e34efa1300");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e34efa1300");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269261");
  script_xref(name:"URL", value:"https://github.com/baresip/baresip/issues/2954");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'baresip' package(s) announced via the FEDORA-2024-e34efa1300 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Baresip v3.10.1 (2024-03-12)

Security Release (possible Denial of Service): A wrong or manipulated incoming RTP Timestamp can cause the baresip process to hang forever, for details see: [#2954]([link moved to references])

 - aureceiver: fix mtx_unlock on discard");

  script_tag(name:"affected", value:"'baresip' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"baresip", rpm:"baresip~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-aac", rpm:"baresip-aac~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-aac-debuginfo", rpm:"baresip-aac-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-alsa", rpm:"baresip-alsa~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-alsa-debuginfo", rpm:"baresip-alsa-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-av1", rpm:"baresip-av1~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-av1-debuginfo", rpm:"baresip-av1-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-codec2", rpm:"baresip-codec2~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-codec2-debuginfo", rpm:"baresip-codec2-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-ctrl_dbus", rpm:"baresip-ctrl_dbus~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-ctrl_dbus-debuginfo", rpm:"baresip-ctrl_dbus-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-debuginfo", rpm:"baresip-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-debugsource", rpm:"baresip-debugsource~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-devel", rpm:"baresip-devel~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-g722", rpm:"baresip-g722~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-g722-debuginfo", rpm:"baresip-g722-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-g726", rpm:"baresip-g726~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-g726-debuginfo", rpm:"baresip-g726-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-gst", rpm:"baresip-gst~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-gst-debuginfo", rpm:"baresip-gst-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-gtk", rpm:"baresip-gtk~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-gtk-debuginfo", rpm:"baresip-gtk-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-jack", rpm:"baresip-jack~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-jack-debuginfo", rpm:"baresip-jack-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-mpa", rpm:"baresip-mpa~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-mpa-debuginfo", rpm:"baresip-mpa-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-mqtt", rpm:"baresip-mqtt~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-mqtt-debuginfo", rpm:"baresip-mqtt-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-opus", rpm:"baresip-opus~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-opus-debuginfo", rpm:"baresip-opus-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-pipewire", rpm:"baresip-pipewire~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-pipewire-debuginfo", rpm:"baresip-pipewire-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-plc", rpm:"baresip-plc~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-plc-debuginfo", rpm:"baresip-plc-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-portaudio", rpm:"baresip-portaudio~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-portaudio-debuginfo", rpm:"baresip-portaudio-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-pulse", rpm:"baresip-pulse~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-pulse-debuginfo", rpm:"baresip-pulse-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-sdl", rpm:"baresip-sdl~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-sdl-debuginfo", rpm:"baresip-sdl-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-snapshot", rpm:"baresip-snapshot~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-snapshot-debuginfo", rpm:"baresip-snapshot-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-sndfile", rpm:"baresip-sndfile~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-sndfile-debuginfo", rpm:"baresip-sndfile-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-tools", rpm:"baresip-tools~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-v4l2", rpm:"baresip-v4l2~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-v4l2-debuginfo", rpm:"baresip-v4l2-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-vp8", rpm:"baresip-vp8~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-vp8-debuginfo", rpm:"baresip-vp8-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-vp9", rpm:"baresip-vp9~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-vp9-debuginfo", rpm:"baresip-vp9-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-x11", rpm:"baresip-x11~3.10.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"baresip-x11-debuginfo", rpm:"baresip-x11-debuginfo~3.10.1~1.fc39", rls:"FC39"))) {
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
