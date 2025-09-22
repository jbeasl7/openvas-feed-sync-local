# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885749");
  script_cve_id("CVE-2023-6693");
  script_tag(name:"creation_date", value:"2024-02-20 02:04:30 +0000 (Tue, 20 Feb 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:04:42 +0000 (Mon, 08 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-c601293124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c601293124");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c601293124");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2256436");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the FEDORA-2024-c601293124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stack buffer overflow in virtio_net_flush_tx (CVE-2023-6693) (rhbz#2256436)");

  script_tag(name:"affected", value:"'qemu' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa-debuginfo", rpm:"qemu-audio-alsa-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus", rpm:"qemu-audio-dbus~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus-debuginfo", rpm:"qemu-audio-dbus-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack", rpm:"qemu-audio-jack~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack-debuginfo", rpm:"qemu-audio-jack-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss-debuginfo", rpm:"qemu-audio-oss-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa-debuginfo", rpm:"qemu-audio-pa-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pipewire", rpm:"qemu-audio-pipewire~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pipewire-debuginfo", rpm:"qemu-audio-pipewire-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl", rpm:"qemu-audio-sdl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl-debuginfo", rpm:"qemu-audio-sdl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice", rpm:"qemu-audio-spice~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice-debuginfo", rpm:"qemu-audio-spice-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-blkio", rpm:"qemu-block-blkio~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-blkio-debuginfo", rpm:"qemu-block-blkio-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg-debuginfo", rpm:"qemu-block-dmg-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster", rpm:"qemu-block-gluster~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster-debuginfo", rpm:"qemu-block-gluster-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs-debuginfo", rpm:"qemu-block-nfs-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-baum", rpm:"qemu-char-baum~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-baum-debuginfo", rpm:"qemu-char-baum-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-spice", rpm:"qemu-char-spice~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-spice-debuginfo", rpm:"qemu-char-spice-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-common", rpm:"qemu-common~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-common-debuginfo", rpm:"qemu-common-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debuginfo", rpm:"qemu-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-qxl", rpm:"qemu-device-display-qxl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-qxl-debuginfo", rpm:"qemu-device-display-qxl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-vhost-user-gpu", rpm:"qemu-device-display-vhost-user-gpu~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-vhost-user-gpu-debuginfo", rpm:"qemu-device-display-vhost-user-gpu-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu", rpm:"qemu-device-display-virtio-gpu~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-ccw", rpm:"qemu-device-display-virtio-gpu-ccw~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-ccw-debuginfo", rpm:"qemu-device-display-virtio-gpu-ccw-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-debuginfo", rpm:"qemu-device-display-virtio-gpu-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-gl", rpm:"qemu-device-display-virtio-gpu-gl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-gl-debuginfo", rpm:"qemu-device-display-virtio-gpu-gl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci", rpm:"qemu-device-display-virtio-gpu-pci~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-debuginfo", rpm:"qemu-device-display-virtio-gpu-pci-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-gl", rpm:"qemu-device-display-virtio-gpu-pci-gl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-gl-debuginfo", rpm:"qemu-device-display-virtio-gpu-pci-gl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga", rpm:"qemu-device-display-virtio-vga~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-debuginfo", rpm:"qemu-device-display-virtio-vga-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-gl", rpm:"qemu-device-display-virtio-vga-gl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-gl-debuginfo", rpm:"qemu-device-display-virtio-vga-gl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-host", rpm:"qemu-device-usb-host~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-host-debuginfo", rpm:"qemu-device-usb-host-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-redirect", rpm:"qemu-device-usb-redirect~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-redirect-debuginfo", rpm:"qemu-device-usb-redirect-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-smartcard", rpm:"qemu-device-usb-smartcard~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-smartcard-debuginfo", rpm:"qemu-device-usb-smartcard-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-docs", rpm:"qemu-docs~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img-debuginfo", rpm:"qemu-img-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-core", rpm:"qemu-kvm-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper", rpm:"qemu-pr-helper~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper-debuginfo", rpm:"qemu-pr-helper-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64", rpm:"qemu-system-aarch64~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64-core", rpm:"qemu-system-aarch64-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64-core-debuginfo", rpm:"qemu-system-aarch64-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha", rpm:"qemu-system-alpha~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha-core", rpm:"qemu-system-alpha-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha-core-debuginfo", rpm:"qemu-system-alpha-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm", rpm:"qemu-system-arm~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm-core", rpm:"qemu-system-arm-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm-core-debuginfo", rpm:"qemu-system-arm-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr", rpm:"qemu-system-avr~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr-core", rpm:"qemu-system-avr-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr-core-debuginfo", rpm:"qemu-system-avr-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-cris", rpm:"qemu-system-cris~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-cris-core", rpm:"qemu-system-cris-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-cris-core-debuginfo", rpm:"qemu-system-cris-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa", rpm:"qemu-system-hppa~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa-core", rpm:"qemu-system-hppa-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa-core-debuginfo", rpm:"qemu-system-hppa-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64", rpm:"qemu-system-loongarch64~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64-core", rpm:"qemu-system-loongarch64-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64-core-debuginfo", rpm:"qemu-system-loongarch64-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k", rpm:"qemu-system-m68k~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k-core", rpm:"qemu-system-m68k-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k-core-debuginfo", rpm:"qemu-system-m68k-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze", rpm:"qemu-system-microblaze~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze-core", rpm:"qemu-system-microblaze-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze-core-debuginfo", rpm:"qemu-system-microblaze-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips", rpm:"qemu-system-mips~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips-core", rpm:"qemu-system-mips-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips-core-debuginfo", rpm:"qemu-system-mips-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-nios2", rpm:"qemu-system-nios2~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-nios2-core", rpm:"qemu-system-nios2-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-nios2-core-debuginfo", rpm:"qemu-system-nios2-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k", rpm:"qemu-system-or1k~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k-core", rpm:"qemu-system-or1k-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k-core-debuginfo", rpm:"qemu-system-or1k-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc", rpm:"qemu-system-ppc~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc-core", rpm:"qemu-system-ppc-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc-core-debuginfo", rpm:"qemu-system-ppc-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv", rpm:"qemu-system-riscv~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv-core", rpm:"qemu-system-riscv-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv-core-debuginfo", rpm:"qemu-system-riscv-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx", rpm:"qemu-system-rx~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx-core", rpm:"qemu-system-rx-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx-core-debuginfo", rpm:"qemu-system-rx-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x", rpm:"qemu-system-s390x~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x-core", rpm:"qemu-system-s390x-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x-core-debuginfo", rpm:"qemu-system-s390x-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4", rpm:"qemu-system-sh4~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4-core", rpm:"qemu-system-sh4-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4-core-debuginfo", rpm:"qemu-system-sh4-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc", rpm:"qemu-system-sparc~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc-core", rpm:"qemu-system-sparc-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc-core-debuginfo", rpm:"qemu-system-sparc-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore", rpm:"qemu-system-tricore~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore-core", rpm:"qemu-system-tricore-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore-core-debuginfo", rpm:"qemu-system-tricore-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86", rpm:"qemu-system-x86~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86-core", rpm:"qemu-system-x86-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86-core-debuginfo", rpm:"qemu-system-x86-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa", rpm:"qemu-system-xtensa~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa-core", rpm:"qemu-system-xtensa-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa-core-debuginfo", rpm:"qemu-system-xtensa-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tests", rpm:"qemu-tests~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tests-debuginfo", rpm:"qemu-tests-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses-debuginfo", rpm:"qemu-ui-curses-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-dbus", rpm:"qemu-ui-dbus~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-dbus-debuginfo", rpm:"qemu-ui-dbus-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-egl-headless", rpm:"qemu-ui-egl-headless~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-egl-headless-debuginfo", rpm:"qemu-ui-egl-headless-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk-debuginfo", rpm:"qemu-ui-gtk-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl", rpm:"qemu-ui-opengl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl-debuginfo", rpm:"qemu-ui-opengl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl", rpm:"qemu-ui-sdl~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl-debuginfo", rpm:"qemu-ui-sdl-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app-debuginfo", rpm:"qemu-ui-spice-app-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core", rpm:"qemu-ui-spice-core~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core-debuginfo", rpm:"qemu-ui-spice-core-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user", rpm:"qemu-user~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-binfmt", rpm:"qemu-user-binfmt~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-debuginfo", rpm:"qemu-user-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static", rpm:"qemu-user-static~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-aarch64", rpm:"qemu-user-static-aarch64~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-aarch64-debuginfo", rpm:"qemu-user-static-aarch64-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-alpha", rpm:"qemu-user-static-alpha~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-alpha-debuginfo", rpm:"qemu-user-static-alpha-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-arm", rpm:"qemu-user-static-arm~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-arm-debuginfo", rpm:"qemu-user-static-arm-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-cris", rpm:"qemu-user-static-cris~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-cris-debuginfo", rpm:"qemu-user-static-cris-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hexagon", rpm:"qemu-user-static-hexagon~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hexagon-debuginfo", rpm:"qemu-user-static-hexagon-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hppa", rpm:"qemu-user-static-hppa~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hppa-debuginfo", rpm:"qemu-user-static-hppa-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-loongarch64", rpm:"qemu-user-static-loongarch64~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-loongarch64-debuginfo", rpm:"qemu-user-static-loongarch64-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-m68k", rpm:"qemu-user-static-m68k~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-m68k-debuginfo", rpm:"qemu-user-static-m68k-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-microblaze", rpm:"qemu-user-static-microblaze~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-microblaze-debuginfo", rpm:"qemu-user-static-microblaze-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-mips", rpm:"qemu-user-static-mips~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-mips-debuginfo", rpm:"qemu-user-static-mips-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-nios2", rpm:"qemu-user-static-nios2~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-nios2-debuginfo", rpm:"qemu-user-static-nios2-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-or1k", rpm:"qemu-user-static-or1k~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-or1k-debuginfo", rpm:"qemu-user-static-or1k-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-ppc", rpm:"qemu-user-static-ppc~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-ppc-debuginfo", rpm:"qemu-user-static-ppc-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-riscv", rpm:"qemu-user-static-riscv~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-riscv-debuginfo", rpm:"qemu-user-static-riscv-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-s390x", rpm:"qemu-user-static-s390x~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-s390x-debuginfo", rpm:"qemu-user-static-s390x-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sh4", rpm:"qemu-user-static-sh4~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sh4-debuginfo", rpm:"qemu-user-static-sh4-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sparc", rpm:"qemu-user-static-sparc~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sparc-debuginfo", rpm:"qemu-user-static-sparc-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-x86", rpm:"qemu-user-static-x86~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-x86-debuginfo", rpm:"qemu-user-static-x86-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-xtensa", rpm:"qemu-user-static-xtensa~8.1.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-xtensa-debuginfo", rpm:"qemu-user-static-xtensa-debuginfo~8.1.3~3.fc39", rls:"FC39"))) {
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
