# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891035");
  script_cve_id("CVE-2016-9602", "CVE-2016-9603", "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086");
  script_tag(name:"creation_date", value:"2018-02-07 23:00:00 +0000 (Wed, 07 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:29:43 +0000 (Thu, 06 Sep 2018)");

  script_name("Debian: Security Advisory (DLA-1035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1035-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-1035-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-1035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in qemu, a fast processor emulator. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-9603

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator and the VNC display driver support is vulnerable to a heap buffer overflow issue. It could occur when Vnc client attempts to update its display after a vga operation is performed by a guest.

A privileged user/process inside guest could use this flaw to crash the Qemu process resulting in DoS OR potentially leverage it to execute arbitrary code on the host with privileges of the Qemu process.

CVE-2017-7718

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator support is vulnerable to an out-of-bounds access issue. It could occur while copying VGA data via bitblt functions cirrus_bitblt_rop_fwd_transp_ and/or cirrus_bitblt_rop_fwd_.

A privileged user inside guest could use this flaw to crash the Qemu process resulting in DoS.

CVE-2017-7980

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator support is vulnerable to an out-of-bounds r/w access issues. It could occur while copying VGA data via various bitblt functions.

A privileged user inside guest could use this flaw to crash the Qemu process resulting in DoS OR potentially execute arbitrary code on a host with privileges of Qemu process on the host.

CVE-2016-9602

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to an improper link following issue. It could occur while accessing symbolic link files on a shared host directory.

A privileged user inside guest could use this flaw to access host file system beyond the shared folder and potentially escalating their privileges on a host.

CVE-2017-7377

Quick Emulator(Qemu) built with the virtio-9p back-end support is vulnerable to a memory leakage issue. It could occur while doing a I/O operation via v9fs_create/v9fs_lcreate routine.

A privileged user/process inside guest could use this flaw to leak host memory resulting in Dos.

CVE-2017-7471

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to an improper access control issue. It could occur while accessing files on a shared host directory.

A privileged user inside guest could use this flaw to access host file system beyond the shared folder and potentially escalating their privileges on a host.

CVE-2017-7493

Quick Emulator(Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to an improper access control issue. It could occur while accessing virtfs metadata files in mapped-file security mode.

A guest user could use this flaw to escalate their privileges inside guest.

CVE-2017-8086

Quick Emulator(Qemu) built with the virtio-9p back-end support is vulnerable to a memory leakage issue. It could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6+deb7u22", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6+deb7u22", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6+deb7u22", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6+deb7u22", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6+deb7u22", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6+deb7u22", rls:"DEB7"))) {
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
