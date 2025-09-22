# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.9974808629");
  script_cve_id("CVE-2023-50711");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:36:27 +0000 (Mon, 08 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-9974808629)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-9974808629");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-9974808629");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firecracker, libkrun, rust-event-manager, rust-kvm-bindings, rust-kvm-ioctls, rust-linux-loader, rust-userfaultfd, rust-versionize, rust-vhost, rust-vhost-user-backend, rust-virtio-queue, rust-vm-memory, rust-vm-superio, rust-vmm-sys-util, virtiofsd' package(s) announced via the FEDORA-2024-9974808629 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update rust-vmm components and their consumers to address CVE-2023-50711");

  script_tag(name:"affected", value:"'firecracker, libkrun, rust-event-manager, rust-kvm-bindings, rust-kvm-ioctls, rust-linux-loader, rust-userfaultfd, rust-versionize, rust-vhost, rust-vhost-user-backend, rust-virtio-queue, rust-vm-memory, rust-vm-superio, rust-vmm-sys-util, virtiofsd' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"firecracker", rpm:"firecracker~1.6.0~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firecracker-debuginfo", rpm:"firecracker-debuginfo~1.6.0~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firecracker-debugsource", rpm:"firecracker-debugsource~1.6.0~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun", rpm:"libkrun~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-debuginfo", rpm:"libkrun-debuginfo~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-debugsource", rpm:"libkrun-debugsource~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-devel", rpm:"libkrun-devel~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev", rpm:"libkrun-sev~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev-debuginfo", rpm:"libkrun-sev-debuginfo~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev-devel", rpm:"libkrun-sev-devel~1.7.2~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-event-manager+default-devel", rpm:"rust-event-manager+default-devel~0.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-event-manager+remote_endpoint-devel", rpm:"rust-event-manager+remote_endpoint-devel~0.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-event-manager+test_utilities-devel", rpm:"rust-event-manager+test_utilities-devel~0.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-event-manager", rpm:"rust-event-manager~0.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-event-manager-devel", rpm:"rust-event-manager-devel~0.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-bindings+default-devel", rpm:"rust-kvm-bindings+default-devel~0.7.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-bindings+fam-wrappers-devel", rpm:"rust-kvm-bindings+fam-wrappers-devel~0.7.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-bindings+vmm-sys-util-devel", rpm:"rust-kvm-bindings+vmm-sys-util-devel~0.7.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-bindings", rpm:"rust-kvm-bindings~0.7.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-bindings-devel", rpm:"rust-kvm-bindings-devel~0.7.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-ioctls+default-devel", rpm:"rust-kvm-ioctls+default-devel~0.16.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-ioctls", rpm:"rust-kvm-ioctls~0.16.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kvm-ioctls-devel", rpm:"rust-kvm-ioctls-devel~0.16.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-linux-loader+bzimage-devel", rpm:"rust-linux-loader+bzimage-devel~0.10.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-linux-loader+default-devel", rpm:"rust-linux-loader+default-devel~0.10.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-linux-loader+elf-devel", rpm:"rust-linux-loader+elf-devel~0.10.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-linux-loader+pe-devel", rpm:"rust-linux-loader+pe-devel~0.10.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-linux-loader", rpm:"rust-linux-loader~0.10.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-linux-loader-devel", rpm:"rust-linux-loader-devel~0.10.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-userfaultfd+default-devel", rpm:"rust-userfaultfd+default-devel~0.8.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-userfaultfd+linux4_14-devel", rpm:"rust-userfaultfd+linux4_14-devel~0.8.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-userfaultfd+linux5_7-devel", rpm:"rust-userfaultfd+linux5_7-devel~0.8.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-userfaultfd", rpm:"rust-userfaultfd~0.8.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-userfaultfd-devel", rpm:"rust-userfaultfd-devel~0.8.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-versionize+default-devel", rpm:"rust-versionize+default-devel~0.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-versionize", rpm:"rust-versionize~0.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-versionize-devel", rpm:"rust-versionize-devel~0.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+default-devel", rpm:"rust-vhost+default-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+test-utils-devel", rpm:"rust-vhost+test-utils-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-kern-devel", rpm:"rust-vhost+vhost-kern-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-net-devel", rpm:"rust-vhost+vhost-net-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-user-backend-devel", rpm:"rust-vhost+vhost-user-backend-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-user-devel", rpm:"rust-vhost+vhost-user-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-user-frontend-devel", rpm:"rust-vhost+vhost-user-frontend-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-vdpa-devel", rpm:"rust-vhost+vhost-vdpa-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+vhost-vsock-devel", rpm:"rust-vhost+vhost-vsock-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost+xen-devel", rpm:"rust-vhost+xen-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost", rpm:"rust-vhost~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-devel", rpm:"rust-vhost-devel~0.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-user-backend+default-devel", rpm:"rust-vhost-user-backend+default-devel~0.13.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-user-backend+xen-devel", rpm:"rust-vhost-user-backend+xen-devel~0.13.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-user-backend", rpm:"rust-vhost-user-backend~0.13.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-user-backend-devel", rpm:"rust-vhost-user-backend-devel~0.13.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-virtio-queue+default-devel", rpm:"rust-virtio-queue+default-devel~0.11.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-virtio-queue+test-utils-devel", rpm:"rust-virtio-queue+test-utils-devel~0.11.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-virtio-queue", rpm:"rust-virtio-queue~0.11.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-virtio-queue-devel", rpm:"rust-virtio-queue-devel~0.11.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+arc-swap-devel", rpm:"rust-vm-memory+arc-swap-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+backend-atomic-devel", rpm:"rust-vm-memory+backend-atomic-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+backend-bitmap-devel", rpm:"rust-vm-memory+backend-bitmap-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+backend-mmap-devel", rpm:"rust-vm-memory+backend-mmap-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+bitflags-devel", rpm:"rust-vm-memory+bitflags-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+default-devel", rpm:"rust-vm-memory+default-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+vmm-sys-util-devel", rpm:"rust-vm-memory+vmm-sys-util-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory+xen-devel", rpm:"rust-vm-memory+xen-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory", rpm:"rust-vm-memory~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-memory-devel", rpm:"rust-vm-memory-devel~0.14.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-superio+default-devel", rpm:"rust-vm-superio+default-devel~0.7.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-superio", rpm:"rust-vm-superio~0.7.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vm-superio-devel", rpm:"rust-vm-superio-devel~0.7.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vmm-sys-util+default-devel", rpm:"rust-vmm-sys-util+default-devel~0.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vmm-sys-util+serde-devel", rpm:"rust-vmm-sys-util+serde-devel~0.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vmm-sys-util+serde_derive-devel", rpm:"rust-vmm-sys-util+serde_derive-devel~0.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vmm-sys-util+with-serde-devel", rpm:"rust-vmm-sys-util+with-serde-devel~0.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vmm-sys-util", rpm:"rust-vmm-sys-util~0.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vmm-sys-util-devel", rpm:"rust-vmm-sys-util-devel~0.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtiofsd", rpm:"virtiofsd~1.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtiofsd-debuginfo", rpm:"virtiofsd-debuginfo~1.10.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtiofsd-debugsource", rpm:"virtiofsd-debugsource~1.10.0~1.fc40", rls:"FC40"))) {
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
