# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0662.1");
  script_cve_id("CVE-2025-14876", "CVE-2026-0665");
  script_tag(name:"creation_date", value:"2026-03-02 04:36:59 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0662-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0662-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260662-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256484");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024448.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2026:0662-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

- CVE-2025-14876: qemu-kvm: Unbounded allocation in virtio-crypto (bsc#1255400).
- CVE-2026-0665: out-of-bounds heap access can lead to a denial of service or potential memory corruption (bsc#1256484).");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-SLOF", rpm:"qemu-SLOF~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-accel-qtest", rpm:"qemu-accel-qtest~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-accel-tcg-x86", rpm:"qemu-accel-tcg-x86~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus", rpm:"qemu-audio-dbus~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack", rpm:"qemu-audio-jack~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pipewire", rpm:"qemu-audio-pipewire~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice", rpm:"qemu-audio-spice~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster", rpm:"qemu-block-gluster~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-chardev-baum", rpm:"qemu-chardev-baum~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-chardev-spice", rpm:"qemu-chardev-spice~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-doc", rpm:"qemu-doc~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-extra", rpm:"qemu-extra~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-headless", rpm:"qemu-headless~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-qxl", rpm:"qemu-hw-display-qxl~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu", rpm:"qemu-hw-display-virtio-gpu~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu-pci", rpm:"qemu-hw-display-virtio-gpu-pci~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-vga", rpm:"qemu-hw-display-virtio-vga~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-s390x-virtio-gpu-ccw", rpm:"qemu-hw-s390x-virtio-gpu-ccw~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-host", rpm:"qemu-hw-usb-host~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-redirect", rpm:"qemu-hw-usb-redirect~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-smartcard", rpm:"qemu-hw-usb-smartcard~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ivshmem-tools", rpm:"qemu-ivshmem-tools~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ksm", rpm:"qemu-ksm~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user", rpm:"qemu-linux-user~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-microvm", rpm:"qemu-microvm~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper", rpm:"qemu-pr-helper~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390x", rpm:"qemu-s390x~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~8.2.101.16.3_3_ga95067eb~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-skiboot", rpm:"qemu-skiboot~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-spice", rpm:"qemu-spice~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-dbus", rpm:"qemu-ui-dbus~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl", rpm:"qemu-ui-opengl~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core", rpm:"qemu-ui-spice-core~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~8.2.101.16.3_3_ga95067eb~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vhost-user-gpu", rpm:"qemu-vhost-user-gpu~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~8.2.10~150600.3.46.1", rls:"openSUSELeap15.6"))) {
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
