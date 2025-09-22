# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123113");
  script_cve_id("CVE-2015-2150", "CVE-2015-3331");
  script_tag(name:"creation_date", value:"2015-10-06 06:48:03 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-3035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3035");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-68.2.2.el6uek, dtrace-modules-3.8.13-68.2.2.el7uek, kernel-uek' package(s) announced via the ELSA-2015-3035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-68.2.2]
- crypto: aesni - fix memory usage in GCM decryption (Stephan Mueller) [Orabug: 21077385] {CVE-2015-3331}

[3.8.13-68.2.1]
- xen/pciback: Don't disable PCI_COMMAND on PCI device reset. (Konrad Rzeszutek Wilk) [Orabug: 20807438] {CVE-2015-2150}
- xen-blkfront: fix accounting of reqs when migrating (Roger Pau Monne) [Orabug: 20860817]
- Doc/cpu-hotplug: Specify race-free way to register CPU hotplug callbacks (Srivatsa S. Bhat) [Orabug: 20917697]
- net/iucv/iucv.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- net/core/flow.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- mm, vmstat: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- profile: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- trace, ring-buffer: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- hwmon, via-cputemp: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- hwmon, coretemp: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- octeon, watchdog: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- oprofile, nmi-timer: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- intel-idle: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- drivers/base/topology.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- acpi-cpufreq: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- scsi, fcoe: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- scsi, bnx2fc: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- scsi, bnx2i: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- arm64, debug-monitors: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- arm64, hw_breakpoint.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, kvm: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, oprofile, nmi: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, pci, amd-bus: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, hpet: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, intel, cacheinfo: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, amd, ibs: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, therm_throt.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, mce: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697]
- x86, intel, uncore: Fix CPU hotplug callback registration (Srivatsa S. Bhat) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-68.2.2.el6uek, dtrace-modules-3.8.13-68.2.2.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-68.2.2.el6uek", rpm:"dtrace-modules-3.8.13-68.2.2.el6uek~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-68.2.2.el7uek", rpm:"dtrace-modules-3.8.13-68.2.2.el7uek~0.4.3~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.2.2.el7uek", rls:"OracleLinux7"))) {
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
