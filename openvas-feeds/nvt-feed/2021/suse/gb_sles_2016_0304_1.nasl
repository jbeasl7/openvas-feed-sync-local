# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0304.1");
  script_cve_id("CVE-2015-0236", "CVE-2015-5313");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 15:20:09 +0000 (Mon, 18 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0304-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160304-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953110");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-February/001840.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2016:0304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libvirt was updated to fix one security issue and several non-security issues.

This security issue was fixed:

- CVE-2015-0236: libvirt allowed remote authenticated users to obtain the VNC
 password by using the VIR_DOMAIN_XML_SECURE flag with a crafted (1) snapshot
 to the virDomainSnapshotGetXMLDesc interface or (2) image to the
 virDomainSaveImageGetXMLDesc interface. (bsc#914693)
- CVE-2015-5313: path traversal vulnerability allowed libvirtd process to write arbitrary files into file system using root permissions (bsc#953110)

Theses non-security issues were fixed:

- bsc#948686: Use PAUSED state for domains that are starting up.
- bsc#903757: Provide nodeGetSecurityModel implementation in libxl.
- bsc#938228: Set disk type to BLOCK when driver is not tap or file.
- bsc#948516: Fix profile_status to distinguish between errors and unconfined domains.
- bsc#936524: Fix error starting lxc containers with direct interfaces.
- bsc#921555: Fixed apparmor generated profile for PCI hostdevs.
- bsc#899334: Include additional upstream fixes for systemd TerminateMachine.
- bsc#921586: Fix security driver default settings in /etc/libvirt/qemu.conf.
- bsc#921355: Fixed a number of QEMU apparmor abstraction problems.
- bsc#911737: Additional fix for the case where security labels aren't automatically set.
- bsc#914297: Allow setting the URL of an SMT server to use in place of SCC.
- bsc#904432: Backported route definition changes.");

  script_tag(name:"affected", value:"'libvirt' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl", rpm:"libvirt-daemon-driver-libxl~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-qemu", rpm:"libvirt-daemon-qemu~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-xen", rpm:"libvirt-daemon-xen~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~1.2.5~27.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.2.5~27.10.1", rls:"SLES12.0"))) {
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
