# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123692");
  script_cve_id("CVE-2012-3411");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:18 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0276)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0276");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0276.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2013-0276 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[libvirt-0.10.2-18.0.1.el6]
- Replace docs/et.png in tarball with blank image

[0.10.2-18]
- rpc: Fix crash on error paths of message dispatching (CVE-2013-0170)
- spec: Disable libssh2 support (rhbz#513363)

[0.10.2-17]
- storage: Fix lvcreate parameter for backingStore. (rhbz#896398)
- qemu: Don't return success if creation of snapshot save file fails (rhbz#896403)
- qemu: Reject attempts to create snapshots with names containing '/' (rhbz#896403)

[0.10.2-16]
- qemu_agent: Remove agent reference only when disposing it (rhbz#892079)
- Add RESUME event listener to qemu monitor. (rhbz#894085)

[0.10.2-15]
- snapshot: conf: Make virDomainSnapshotIsExternal more reusable (rhbz#889407)
- snapshot: qemu: Separate logic blocks with newlines (rhbz#889407)
- snapshot: qemu: Fix segfault and vanishing snapshots when redefining (rhbz#889407)
- snapshot: qemu: Allow redefinition of external snapshots (rhbz#889407)
- util: Prepare helpers for unpriv_sgio setting (rhbz#878578)
- qemu: Add a hash table for the shared disks (rhbz#878578)
- docs: Add docs and rng schema for new XML tag sgio (rhbz#878578)
- conf: Parse and format the new XML (rhbz#878578)
- qemu: Set unpriv_sgio when starting domain and attaching disk (rhbz#878578)
- qemu: Check if the shared disk's cdbfilter conflicts with others (rhbz#878578)
- qemu: Relax hard RSS limit (rhbz#891653)

[0.10.2-14]
- util: Add missing error log messages when failing to get netlink VFINFO (rhbz#889319)
- util: Fix functions that retrieve SRIOV VF info (rhbz#889319)
- util: Fix botched check for new netlink request filters (rhbz#889319)
- blockjob: Fix memleak that prevented block pivot (rhbz#888426)
- sanlock: Chown lease files as well (rhbz#820173)

[0.10.2-13]
- network: Prevent dnsmasq from listening on localhost (rhbz#886821)
- sanlock: Re-add lockspace unconditionally (rhbz#820173)
- Fix 'virsh create' example (rhbz#887187)
- docs: Fix some typos in examples (rhbz#887187)
- network: Don't require private addresses if dnsmasq uses SO_BINDTODEVICE (rhbz#882265)

[0.10.2-12]
- qemu: Eliminate bogus error log when changing netdev's bridge (rhbz#885838)
- remote: Avoid the thread race condition (rhbz#866524)
- storage: Error out earlier if the volume target path already exists (rhbz#832302)
- dnsmasq: Fix parsing of the version number (rhbz#885727)
- qemu: Restart CPUs with valid async job type when doing external snapshots (rhbz#885081)
- examples: Fix balloon event callback (rhbz#884650)
- util: Don't fail virGetGroupIDByName when group not found (rhbz#883832)
- util: Don't fail virGetUserIDByName when user not found (rhbz#883832)
- util: Rework error reporting in virGet(User<pipe>Group)IDByName (rhbz#883832)
- util: Fix warning message in previous patch (rhbz#883832)

[0.10.2-11]
- Fix uninitialized variable in virLXCControllerSetupDevPTS (rhbz#880064)
- storage: Fix device detach regression with cgroup ACLs (rhbz#876828)
- storage: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~18.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.0.1.el6", rls:"OracleLinux6"))) {
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
