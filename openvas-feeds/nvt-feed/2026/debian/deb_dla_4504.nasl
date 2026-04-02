# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2026.4504");
  script_tag(name:"creation_date", value:"2026-03-23 04:46:52 +0000 (Mon, 23 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-4504-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4504-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2026/DLA-4504-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DLA-4504-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss-libvirt", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-clients", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-config-network", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-config-nwfilter", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-lxc", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-qemu", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-storage-gluster", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-storage-iscsi-direct", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-storage-rbd", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-storage-zfs", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-vbox", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-driver-xen", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system-systemd", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system-sysv", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-dev", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-doc", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-login-shell", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-sanlock", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-wireshark", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"7.0.0-3+deb11u4", rls:"DEB11"))) {
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
