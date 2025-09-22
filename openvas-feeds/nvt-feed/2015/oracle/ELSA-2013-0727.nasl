# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123647");
  script_cve_id("CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:45 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0727)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0727");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0727.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2013-0727 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-262.0.1.el5_9.3]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch
- Added kvm-Introduce-oel-machine-type.patch

[kvm-83-262.el5_3]
- kvm-kernel-kvm-accept-unaligned-MSR_KVM_SYSTEM_TIME-writes.patch [bz#947363]
- Resolves: bz#947363
 (RHEL.5.8.32 guest hang when installing)

[kvm-83-262.el5_2]
- kvm-kernel-KVM-Fix-for-buffer-overflow-in-handling-of-MSR_KVM_S.patch [bz#917018]
- kvm-kernel-KVM-Convert-MSR_KVM_SYSTEM_TIME-to-use-kvm_write_gue.patch [bz#917022]
- kvm-kernel-KVM-Fix-bounds-checking-in-ioapic-indirect-register-.patch [bz#917028]
- kvm-kernel-do-not-GP-on-unaligned-MSR_KVM_SYSTEM_TIME-write.patch [bz#bz917019]
- Resolves: bz#917018
 (CVE-2013-1796 kernel: kvm: buffer overflow in handling of MSR_KVM_SYSTEM_TIME [rhel-5.9.z])
- Resolves: bz#917022
 (CVE-2013-1797 kernel: kvm: after free issue with the handling of MSR_KVM_SYSTEM_TIME [rhel-5.9.z])
- Resolves: bz#917028
 (CVE-2013-1798 kernel: kvm: out-of-bounds access in ioapic indirect register reads [rhel-5.9.z])");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~262.0.1.el5_9.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~262.0.1.el5_9.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~262.0.1.el5_9.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~262.0.1.el5_9.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~262.0.1.el5_9.3", rls:"OracleLinux5"))) {
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
