# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123916");
  script_cve_id("CVE-2012-1601", "CVE-2012-2121");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:15 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0676)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0676");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0676.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2012-0676 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-249.0.1.el5_8.4]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch
- Added kvm-Introduce-oel-machine-type.patch

[kvm-83-249.el5_8.4]
- kvm-kernel-KVM-unmap-pages-from-the-iommu-when-slots-are-remove.patch [bz#814151]
- CVE: CVE-2012-2121
- Resolves: bz#814151
 (CVE-2012-2121 kvm: device assignment page leak [rhel-5.8])

[kvm-83-249.el5_8.3]
- kvm-fix-l1_map-buffer-overflow.patch [bz#816207]
- Resolves: bz#816207
 (qemu-kvm segfault in tb_invalidate_phys_page_range())

[kvm-83-249.el5_8.2]
- kvm-kernel-KVM-Ensure-all-vcpus-are-consistent-with-in-kernel-i.patch [bz#808205]
- Resolves: bz#808205
 (CVE-2012-1601 kernel: kvm: irqchip_in_kernel() and vcpu->arch.apic inconsistency [rhel-5.8.z])

[kvm-83-249.el5_8.1]
- kvm-posix-aio-compat-fix-thread-accounting-leak.patch [bz#802429]
- Resolves: bz#802429
 ([RHEL5.8 Snapshot2]RHEL5.8 KVMGuest hung during Guest OS booting up)");

  script_tag(name:"affected", value:"'kvm' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~249.0.1.el5_8.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~249.0.1.el5_8.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~249.0.1.el5_8.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~249.0.1.el5_8.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~249.0.1.el5_8.4", rls:"OracleLinux5"))) {
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
