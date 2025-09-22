# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123362");
  script_cve_id("CVE-2014-2894");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:47 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-0704)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0704");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0704.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2014-0704 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.3-60.el7_0.2]
- kvm-pc-add-hot_add_cpu-callback-to-all-machine-types.patch [bz#1094820]
- Resolves: bz#1094820
 (Hot plug CPU not working with RHEL6 machine types running on RHEL7 host.)

[1.5.3-60.el7_0.1]
- kvm-iscsi-fix-indentation.patch [bz#1090978]
- kvm-iscsi-correctly-propagate-errors-in-iscsi_open.patch [bz#1090978]
- kvm-block-iscsi-query-for-supported-VPD-pages.patch [bz#1090978]
- kvm-block-iscsi-fix-segfault-if-writesame-fails.patch [bz#1090978]
- kvm-iscsi-recognize-invalid-field-ASCQ-from-WRITE-SAME-c.patch [bz#1090978]
- kvm-iscsi-ignore-flushes-on-scsi-generic-devices.patch [bz#1090978]
- kvm-iscsi-always-query-max-WRITE-SAME-length.patch [bz#1090978]
- kvm-iscsi-Don-t-set-error-if-already-set-in-iscsi_do_inq.patch [bz#1090978]
- kvm-iscsi-Remember-to-set-ret-for-iscsi_open-in-error-ca.patch [bz#1090978]
- kvm-qemu_loadvm_state-shadow-SeaBIOS-for-VM-incoming-fro.patch [1091322]
- kvm-uhci-UNfix-irq-routing-for-RHEL-6-machtypes-RHEL-onl.patch [bz#1090981]
- kvm-ide-Correct-improper-smart-self-test-counter-reset-i.patch [bz#1093612]
- Resolves: bz#1091322
 (fail to reboot guest after migration from RHEL6.5 host to RHEL7.0 host)
- Resolves: bz#1090981
 (Guest hits call trace migrate from RHEL6.5 to RHEL7.0 host with -M 6.1 & balloon & uhci device)
- Resolves: bz#1090978
 (qemu-kvm: iSCSI: Failure. SENSE KEY:ILLEGAL_REQUEST(5) ASCQ:INVALID_FIELD_IN_CDB(0x2400))
- Resolves: bz#1093612
 (CVE-2014-2894 qemu-kvm: QEMU: out of bounds buffer accesses, guest triggerable via IDE SMART [rhel-7.0.z])");

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

  if(!isnull(res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.2", rls:"OracleLinux7"))) {
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
