# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123071");
  script_cve_id("CVE-2015-3214", "CVE-2015-5154");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:59 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1507");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1507.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2015-1507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.3-86.el7_1.5]
- kvm-i8254-fix-out-of-bounds-memory-access-in-pit_ioport_.patch [bz#1243726]
- Resolves: bz#1243726
 (CVE-2015-3214 qemu-kvm: qemu: i8254: out-of-bounds memory access in pit_ioport_read function [rhel-7.1.z])

[1.5.3-86.el7_1.4]
- kvm-ide-Check-array-bounds-before-writing-to-io_buffer-C.patch [bz#1243689]
- kvm-ide-atapi-Fix-START-STOP-UNIT-command-completion.patch [bz#1243689]
- kvm-ide-Clear-DRQ-after-handling-all-expected-accesses.patch [bz#1243689]
- Resolves: bz#1243689
 (EMBARGOED CVE-2015-5154 qemu-kvm: qemu: ide: atapi: heap overflow during I/O buffer memory access [rhel-7.1.z])

[1.5.3-86.el7_1.3]
- kvm-atomics-add-explicit-compiler-fence-in-__atomic-memo.patch [bz#1233643]
- Resolves: bz#1233643
 ([abrt] qemu-kvm: bdrv_error_action(): qemu-kvm killed by SIGABRT)");

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

  if(!isnull(res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~86.el7_1.5", rls:"OracleLinux7"))) {
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
