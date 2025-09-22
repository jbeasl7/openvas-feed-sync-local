# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123165");
  script_cve_id("CVE-2014-8136", "CVE-2015-0236");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:11 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-0323)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0323");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0323.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2015-0323 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.8-16.0.1]
- Replace docs/et.png in tarball with blank image

[1.2.8-16]
- qemu: don't setup cpuset.mems if memory mode in numatune is not 'strict' (rhbz#1186094)
- lxc: don't setup cpuset.mems if memory mode in numatune is not 'strict' (rhbz#1186094)

[1.2.8-15]
- qemu: Add missing goto error in qemuRestoreCgroupState (rhbz#1161540)

[1.2.8-14]
- virNetworkDefUpdateIPDHCPHost: Don't crash when updating network (rhbz#1182486)
- Format CPU features even for host-model (rhbz#1182448)
- util: Add function virCgroupHasEmptyTasks (rhbz#1161540)
- util: Add virNumaGetHostNodeset (rhbz#1161540)
- qemu: Remove unnecessary qemuSetupCgroupPostInit function (rhbz#1161540)
- qemu: Save numad advice into qemuDomainObjPrivate (rhbz#1161540)
- qemu: Leave cpuset.mems in parent cgroup alone (rhbz#1161540)
- qemu: Fix hotplugging cpus with strict memory pinning (rhbz#1161540)
- util: Fix possible NULL dereference (rhbz#1161540)
- qemu_driver: fix setting vcpus for offline domain (rhbz#1161540)
- qemu: migration: Unlock vm on failed ACL check in protocol v2 APIs (CVE-2014-8136)
- CVE-2015-0236: qemu: Check ACLs when dumping security info from save image (CVE-2015-0236)
- CVE-2015-0236: qemu: Check ACLs when dumping security info from snapshots (CVE-2015-0236)
- Check for domain liveness in qemuDomainObjExitMonitor (rhbz#1161024)
- Mark the domain as active in qemuhotplugtest (rhbz#1161024)
- Fix vmdef usage while in monitor in qemuDomainHotplugVcpus (rhbz#1161024)
- Fix vmdef usage while in monitor in BlockStat* APIs (rhbz#1161024)
- Fix vmdef usage while in monitor in qemu process (rhbz#1161024)
- Fix vmdef usage after domain crash in monitor on device detach (rhbz#1161024)
- Fix vmdef usage after domain crash in monitor on device attach (rhbz#1161024)

[1.2.8-13]
- conf: Fix memory leak when parsing invalid network XML (rhbz#1180136)
- qxl: change the default value for vgamem_mb to 16 MiB (rhbz#1181052)
- qemuxml2argvtest: Fix test after change of qxl vgamem_mb default (rhbz#1181052)
- conf: fix crash when hotplug a channel chr device with no target (rhbz#1181408)
- qemu: forbid second blockcommit during active commit (rhbz#1135339)
- qemu_monitor: introduce new function to get QOM path (rhbz#1180574)
- qemu_process: detect updated video ram size values from QEMU (rhbz#1180574)

[1.2.8-12]
- Fix hotplugging of block device-backed usb disks (rhbz#1175668)
- qemu: Create memory-backend-{ram, file} if needed (rhbz#1175397)
- conf: Don't format actual network definition in migratable XML (rhbz#1177194)

[1.2.8-11]
- virsh: vol-upload disallow negative offset (rhbz#1087104)
- storage: fix crash caused by no check return before set close (rhbz#1087104)
- qemu: Fix virsh freeze when blockcopy storage file is removed (rhbz#1139567)
- security: Manage SELinux labels on shared/readonly hostdev's (rhbz#1082521)
- nwfilter: fix crash when adding non-existing nwfilter (rhbz#1169409)
- conf: Fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-login-shell", rpm:"libvirt-login-shell~1.2.8~16.0.1.el7", rls:"OracleLinux7"))) {
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
