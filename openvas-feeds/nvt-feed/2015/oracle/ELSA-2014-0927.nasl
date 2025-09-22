# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123367");
  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 14:39:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Oracle: Security Advisory (ELSA-2014-0927)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0927");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0927.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2014-0927 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.3-60.el7_0.5]
- kvm-Allow-mismatched-virtio-config-len.patch [bz#1095782]
- Resolves: bz#1095782
 (CVE-2014-0182 qemu-kvm: qemu: virtio: out-of-bounds buffer write on state load with invalid config_len [rhel-7.0.z])

[1.5.3-60.el7_0.4]
- kvm-zero-initialize-KVM_SET_GSI_ROUTING-input.patch [bz#1110693]
- kvm-skip-system-call-when-msi-route-is-unchanged.patch [bz#1110693]
- Resolves: bz#1110693
 (2x RHEL 5.10 VM running on RHEL 7 KVM have low TCP_STREAM throughput)

[1.5.3-60.el7_0.3]
- kvm-virtio-net-fix-buffer-overflow-on-invalid-state-load.patch [bz#1095677]
- kvm-virtio-net-out-of-bounds-buffer-write-on-load.patch [bz#1095684]
- kvm-virtio-net-out-of-bounds-buffer-write-on-invalid-sta.patch [bz#1095689]
- kvm-virtio-out-of-bounds-buffer-write-on-invalid-state-l.patch [bz#1095694]
- kvm-virtio-avoid-buffer-overrun-on-incoming-migration.patch [bz#1095737]
- kvm-virtio-scsi-fix-buffer-overrun-on-invalid-state-load.patch [bz#1095741]
- kvm-virtio-validate-config_len-on-load.patch [bz#1095782]
- kvm-virtio-validate-num_sg-when-mapping.patch [bz#1095765]
- kvm-virtio-allow-mapping-up-to-max-queue-size.patch [bz#1095765]
- kvm-vmstate-add-VMS_MUST_EXIST.patch [bz#1095706]
- kvm-vmstate-add-VMSTATE_VALIDATE.patch [bz#1095706]
- kvm-hpet-fix-buffer-overrun-on-invalid-state-load.patch [bz#1095706]
- kvm-hw-pci-pcie_aer.c-fix-buffer-overruns-on-invalid-sta.patch [bz#1095714]
- kvm-usb-sanity-check-setup_index-setup_len-in-post_load.patch [bz#1095746]
- kvm-usb-sanity-check-setup_index-setup_len-in-post_l2.patch [bz#1095746]
- kvm-usb-fix-up-post-load-checks.patch [bz#1096828]
- kvm-XBZRLE-Fix-qemu-crash-when-resize-the-xbzrle-cache.patch [bz#1110191]
- kvm-Provide-init-function-for-ram-migration.patch [bz#1110191]
- kvm-Init-the-XBZRLE.lock-in-ram_mig_init.patch [bz#1110191]
- kvm-XBZRLE-Fix-one-XBZRLE-corruption-issues.patch [bz#1110191]
- kvm-Count-used-RAMBlock-pages-for-migration_dirty_pages.patch [bz#1110189]
- kvm-qcow-correctly-propagate-errors.patch [bz#1097229]
- kvm-qcow1-Make-padding-in-the-header-explicit.patch [bz#1097229]
- kvm-qcow1-Check-maximum-cluster-size.patch [bz#1097229]
- kvm-qcow1-Validate-L2-table-size-CVE-2014-0222.patch [bz#1097229]
- kvm-qcow1-Validate-image-size-CVE-2014-0223.patch [bz#1097236]
- kvm-qcow1-Stricter-backing-file-length-check.patch [bz#1097236]
- kvm-char-restore-read-callback-on-a-reattached-hotplug-c.patch [bz#1110219]
- kvm-qcow2-Free-preallocated-zero-clusters.patch [bz#1110188]
- kvm-qemu-iotests-Discard-preallocated-zero-clusters.patch [bz#1110188]
- Resolves: bz#1095677
 (CVE-2013-4148 qemu-kvm: qemu: virtio-net: buffer overflow on invalid state load [rhel-7.0.z])
- Resolves: bz#1095684
 (CVE-2013-4149 qemu-kvm: qemu: virtio-net: out-of-bounds buffer write on load [rhel-7.0.z])
- Resolves: bz#1095689
 (CVE-2013-4150 qemu-kvm: qemu: virtio-net: out-of-bounds buffer write on invalid state load [rhel-7.0.z])
- Resolves: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.5", rls:"OracleLinux7"))) {
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
