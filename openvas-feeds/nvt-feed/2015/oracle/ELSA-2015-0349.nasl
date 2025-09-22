# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123166");
  script_cve_id("CVE-2014-3640", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:12 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0349)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0349");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0349.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2015-0349 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.3-86.el7]
- kvm-vfio-pci-Fix-interrupt-disabling.patch [bz#1180942]
- kvm-cirrus-fix-blit-region-check.patch [bz#1169456]
- kvm-cirrus-don-t-overflow-CirrusVGAState-cirrus_bltbuf.patch [bz#1169456]
- Resolves: bz#1169456
 (CVE-2014-8106 qemu-kvm: qemu: cirrus: insufficient blit region checks [rhel-7.1])
- Resolves: bz#1180942
 (qemu core dumped when unhotplug gpu card assigned to guest)

[1.5.3-85.el7]
- kvm-block-delete-cow-block-driver.patch [bz#1175325]
- Resolves: bz#1175325
 (Delete cow block driver)

[1.5.3-84.el7]
- kvm-qemu-iotests-Test-case-for-backing-file-deletion.patch [bz#1002493]
- kvm-qemu-iotests-Add-sample-image-and-test-for-VMDK-vers.patch [bz#1134237]
- kvm-vmdk-Check-VMFS-extent-line-field-number.patch [bz#1134237]
- kvm-qemu-iotests-Introduce-_unsupported_imgopts.patch [bz#1002493]
- kvm-qemu-iotests-Add-_unsupported_imgopts-for-vmdk-subfo.patch [bz#1002493]
- kvm-vmdk-Fix-big-flat-extent-IO.patch [bz#1134241]
- kvm-vmdk-Check-for-overhead-when-opening.patch [bz#1134251]
- kvm-block-vmdk-add-basic-.bdrv_check-support.patch [bz#1134251]
- kvm-qemu-iotest-Make-077-raw-only.patch [bz#1134237]
- kvm-qemu-iotests-Don-t-run-005-on-vmdk-split-formats.patch [bz#1002493]
- kvm-vmdk-extract-vmdk_read_desc.patch [bz#1134251]
- kvm-vmdk-push-vmdk_read_desc-up-to-caller.patch [bz#1134251]
- kvm-vmdk-do-not-try-opening-a-file-as-both-image-and-des.patch [bz#1134251]
- kvm-vmdk-correctly-propagate-errors.patch [bz#1134251]
- kvm-block-vmdk-do-not-report-file-offset-for-compressed-.patch [bz#1134251]
- kvm-vmdk-Fix-d-and-lld-to-PRI-in-format-strings.patch [bz#1134251]
- kvm-vmdk-Fix-x-to-PRIx32-in-format-strings-for-cid.patch [bz#1134251]
- kvm-qemu-img-Convert-by-cluster-size-if-target-is-compre.patch [bz#1134283]
- kvm-vmdk-Implement-.bdrv_write_compressed.patch [bz#1134283]
- kvm-vmdk-Implement-.bdrv_get_info.patch [bz#1134283]
- kvm-qemu-iotests-Test-converting-to-streamOptimized-from.patch [bz#1134283]
- kvm-vmdk-Fix-local_err-in-vmdk_create.patch [bz#1134283]
- kvm-fpu-softfloat-drop-INLINE-macro.patch [bz#1002493]
- kvm-block-New-bdrv_nb_sectors.patch [bz#1002493]
- kvm-vmdk-Optimize-cluster-allocation.patch [bz#1002493]
- kvm-vmdk-Handle-failure-for-potentially-large-allocation.patch [bz#1002493]
- kvm-vmdk-Use-bdrv_nb_sectors-where-sectors-not-bytes-are.patch [bz#1002493]
- kvm-vmdk-fix-vmdk_parse_extents-extent_file-leaks.patch [bz#1002493]
- kvm-vmdk-fix-buf-leak-in-vmdk_parse_extents.patch [bz#1002493]
- kvm-vmdk-Fix-integer-overflow-in-offset-calculation.patch [bz#1002493]
- kvm-migration-fix-parameter-validation-on-ram-load-CVE-2.patch [bz#1163078]
- Resolves: bz#1002493
 (qemu-img convert rate about 100k/second from qcow2/raw to vmdk format on nfs system file)
- Resolves: bz#1134237
 (Opening malformed VMDK description file should fail)
- Resolves: bz#1134241
 (QEMU fails to correctly read/write on VMDK with big flat extent)
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

  if(!isnull(res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~86.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~86.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~86.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~86.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~86.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~86.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~86.el7", rls:"OracleLinux7"))) {
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
