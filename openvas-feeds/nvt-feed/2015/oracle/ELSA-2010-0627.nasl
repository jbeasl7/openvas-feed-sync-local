# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122328");
  script_cve_id("CVE-2010-0431", "CVE-2010-0435", "CVE-2010-2784");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0627)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0627");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0627.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2010-0627 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-164.0.1.el5_5.21]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch
- Added kvm-Introduce-oel-machine-type.patch

[kvm-83-164.el5_5.21]
- kvm-Fix-segfault-in-mmio-subpage-handling-code.patch [bz#619412]
- Resolves: bz#619412
 (CVE-2010-2784 qemu: insufficient constraints checking in exec.c:subpage_register() [rhel-5.5.z])

[kvm-83-164.el5_5.20]
- kvm-virtio-net-correct-packet-length-checks.patch [bz#610343]
- Resolves: bz#610343
 (Virtio: Transfer file caused guest in same vlan abnormally quit)

[kvm-83-164.el5_5.19]
- kvm-qcow2-Fix-qemu-img-check-segfault-on-corrupted-image.patch [bz#610342]
- kvm-qcow2-Don-t-try-to-check-tables-that-couldn-t-be-loa.patch [bz#610342]
- kvm-qemu-img-check-Distinguish-different-kinds-of-errors.patch [bz#618206]
- kvm-qcow2-Change-check-to-distinguish-error-cases.patch [bz#618206]
- Resolves: bz#610342
 ([kvm] segmentation fault when running qemu-img check on faulty image)
- Resolves: bz#618206
 ([kvm] qemu image check returns cluster errors when using virtIO block (thinly provisioned) during e_no_space events (along with EIO errors))

[kvm-83-164.el5_5.18]
- kvm-New-slots-need-dirty-tracking-enabled-when-migrating.patch [bz#618205]
- Resolves: bz#618205
 (SPICE - race in KVM/Spice would cause migration to fail (slots are not registered properly?))

[kvm-83-164.el5_5.17]
- kvm-kernel-KVM-MMU-fix-conflict-access-permissions-in-direct-sp.patch [bz#616796]
- Resolves: bz#616796
 (KVM uses wrong permissions for large guest pages)

[kvm-83-164.el5_5.16]
- kvm-kernel-fix-null-pointer-dereference.patch [bz#570531]
 - Resolves: bz#570531
 - CVE: CVE-2010-0435
- kvm-qemu-fix-unsafe-ring-handling.patch [bz#568816]
 - Resolves: bz#568816
 - CVE: CVE-2010-0431");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~164.0.1.el5_5.21", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~164.0.1.el5_5.21", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~164.0.1.el5_5.21", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~164.0.1.el5_5.21", rls:"OracleLinux5"))) {
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
