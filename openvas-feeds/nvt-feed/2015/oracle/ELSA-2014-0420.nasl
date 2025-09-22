# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123423");
  script_cve_id("CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:36 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-03 14:26:00 +0000 (Mon, 03 Oct 2022)");

  script_name("Oracle: Security Advisory (ELSA-2014-0420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0420");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0420.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2014-0420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.12.1.2-2.415.el6_5.8]
- kvm-virtio-net-fix-guest-triggerable-buffer-overrun.patch [bz#1078605 bz#1078849]
- kvm-qcow2-Check-backing_file_offset-CVE-2014-0144.patch [bz#1079452 bz#1079453]
- kvm-qcow2-Check-refcount-table-size-CVE-2014-0144.patch [bz#1079452 bz#1079453]
- kvm-qcow2-Validate-refcount-table-offset.patch [bz#1079518 bz#1086678]
- kvm-qcow2-Validate-snapshot-table-offset-size-CVE-2014-0.patch [bz#1079452 bz#1079453]
- kvm-qcow2-Validate-active-L1-table-offset-and-size-CVE-2.patch [bz#1079452 bz#1079453]
- kvm-qcow2-Fix-backing-file-name-length-check.patch [bz#1079518 bz#1086678]
- kvm-qcow2-Don-t-rely-on-free_cluster_index-in-alloc_refc.patch [bz#1079337 bz#1079338]
- kvm-qcow2-Avoid-integer-overflow-in-get_refcount-CVE-201.patch [bz#1079318 bz#1079319]
- kvm-qcow2-Check-new-refcount-table-size-on-growth.patch [bz#1079518 bz#1086678]
- kvm-qcow2-Fix-types-in-qcow2_alloc_clusters-and-alloc_cl.patch [bz#1079518 bz#1086678]
- kvm-qcow2-Protect-against-some-integer-overflows-in-bdrv.patch [bz#1079518 bz#1086678]
- kvm-qcow2-Catch-some-L1-table-index-overflows.patch [bz#1079518 bz#1086678]
- kvm-qcow2-Fix-new-L1-table-size-check-CVE-2014-0143.patch [bz#1079318 bz#1079319]
- kvm-qcow2-Fix-NULL-dereference-in-qcow2_open-error-path-.patch [bz#1079330 bz#1079331]
- kvm-qcow2-Limit-snapshot-table-size.patch [bz#1079518 bz#1086678]
- kvm-block-cloop-validate-block_size-header-field-CVE-201.patch [bz#1079452 bz#1079453]
- kvm-block-cloop-prevent-offsets_size-integer-overflow-CV.patch [bz#1079318 bz#1079319]
- kvm-block-cloop-refuse-images-with-huge-offsets-arrays-C.patch [bz#1079452 bz#1079453]
- kvm-block-cloop-Fix-coding-style.patch [bz#1079518 bz#1086678]
- kvm-cloop-Fix-bdrv_open-error-handling.patch [bz#1079518 bz#1086678]
- kvm-block-cloop-refuse-images-with-bogus-offsets-CVE-201.patch [bz#1079452 bz#1079453]
- kvm-block-cloop-Use-g_free-instead-of-free.patch [bz#1079518 bz#1086678]
- kvm-block-cloop-fix-offsets-size-off-by-one.patch [bz#1079518 bz#1086678]
- kvm-bochs-Fix-bdrv_open-error-handling.patch [bz#1079518 bz#1086678]
- kvm-bochs-Unify-header-structs-and-make-them-QEMU_PACKED.patch [bz#1079518 bz#1086678]
- kvm-bochs-Use-unsigned-variables-for-offsets-and-sizes-C.patch [bz#1079337 bz#1079338]
- kvm-bochs-Check-catalog_size-header-field-CVE-2014-0143.patch [bz#1079318 bz#1079319]
- kvm-bochs-Check-extent_size-header-field-CVE-2014-0142.patch [bz#1079313 bz#1079314]
- kvm-bochs-Fix-bitmap-offset-calculation.patch [bz#1079518 bz#1086678]
- kvm-vpc-vhd-add-bounds-check-for-max_table_entries-and-b.patch [bz#1079452 bz#1079453]
- kvm-vpc-Validate-block-size-CVE-2014-0142.patch [bz#1079313 bz#1079314]
- kvm-vdi-add-bounds-checks-for-blocks_in_image-and-disk_s.patch [bz#1079452 bz#1079453]
- kvm-vhdx-Bounds-checking-for-block_size-and-logical_sect.patch [bz#1079343 bz#1079344]
- kvm-curl-check-data-size-before-memcpy-to-local-buffer.-.patch [bz#1079452 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.8", rls:"OracleLinux6"))) {
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
