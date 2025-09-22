# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123885");
  script_cve_id("CVE-2012-2693");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0748)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0748");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0748.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2012-0748 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[libvirt-0.9.10-21.0.1.el6]
- Replace docs/et.png in tarball with blank image

[libvirt-0.9.10-21.el6]
- qemu: Rollback on used USB devices (rhbz#743671)
- qemu: Don't delete USB device on failed qemuPrepareHostdevUSBDevices (rhbz#743671)
- Revert 'rpc: Discard non-blocking calls only when necessary' (rhbz#821468)

[libvirt-0.9.10-20.el6]
- Fix virDomainDeviceInfoIsSet() to check all struct fields (rhbz#820869)
- Fix logic for assigning PCI addresses to USB2 companion controllers (rhbz#820869)
- Set a sensible default master start port for ehci companion controllers (rhbz#820869)

[libvirt-0.9.10-19.el6]
- build: Fix the typo in configure.ac (rhbz#820461)
- qemu: Fix build when !HAVE_NUMACTL (rhbz#820461)
- usb: Fix crash when failing to attach a second usb device (rhbz#815755)
- qemu: Use the CPU index in capabilities to map NUMA node to cpu list. (rhbz#820461)
- qemu: Set memory policy using cgroup if placement is auto (rhbz#820461)

[libvirt-0.9.10-18.el6]
- numad: Set memory policy from numad advisory nodeset (rhbz#810157)
[by default (rhbz#810157)]
[(rhbz#810157)]
- qemu: Avoid the memory allocation and freeing (rhbz#810157)
- numad: Divide cur_balloon by 1024 before passing it to numad (rhbz#810157)
- numad: Check numactl-devel if compiled with numad support (rhbz#810157)

[libvirt-0.9.10-17.el6]
- qemu: Don't modify domain on failed blockiotune (rhbz#819014)
- qemu: Reject blockiotune if qemu too old (rhbz#819014)
- qemu: Don't use virDomainDefFormat* directly (rhbz#815503)
- qemu: Emit compatible XML when migrating a domain (rhbz#815503)
- usb: Create functions to search usb device accurately (rhbz#815755)
- qemu: Call usb search function for hostdev initialization and hotplug (rhbz#815755)
- virsh: Avoid heap corruption leading to virsh abort (rhbz#819636)
- util: Fix libvirtd startup failure due to netlink error (rhbz#816465)
- util: Allow specifying both src and dst pid in virNetlinkCommand (rhbz#816465)
- util: Function to get local nl_pid used by netlink event socket (rhbz#816465)
- util: Set src_pid for virNetlinkCommand when appropriate (rhbz#816465)
- domain_conf: Add 'usbredir' to list of valid spice channels (rhbz#819498)
- domain_conf: Add 'default' to list of valid spice channels (rhbz#819499)
- snapshot: Allow block devices past cgroup (rhbz#810200)
- blockjob: Allow block devices past cgroup (rhbz#810200)
- util: Avoid libvirtd crash in virNetDevTapCreate (rhbz#817234)
- python: Fix the forward_null error in Python binding codes (rhbz#771021)
- xen: Fix resource leak in xen driver (rhbz#771021)
- test: Fix resource leak in test driver (rhbz#771021)
- node: Fix resource leak in nodeinfo.c (rhbz#771021)
- virnet: Fix resource leak in virnetlink.c (rhbz#771021)
- vmx: Fix resource leak (rhbz#771021)
- qemu: Fix resource leak (rhbz#771021)
- uuid: Fix possible non-terminated string (rhbz#771021)
- node_device: Fix possible non-terminated string ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.9.10~21.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.9.10~21.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.9.10~21.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.9.10~21.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.9.10~21.0.1.el6", rls:"OracleLinux6"))) {
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
