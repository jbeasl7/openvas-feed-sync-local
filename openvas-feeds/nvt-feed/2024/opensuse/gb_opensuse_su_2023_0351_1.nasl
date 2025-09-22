# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833275");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-22098", "CVE-2023-22099", "CVE-2023-22100");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 22:15:08 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:10 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2023:0351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0351-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XMZ3YIKSP2NRCTNSEI3YU3MKDLRBOPRF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2023:0351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

  - Version bump to VirtualBox 7.0.12 (released October 17 2023 by Oracle)

       Fixes the following:

  - CVE-2023-22098 (boo#1216363)

  - CVE-2023-22099 (boo#1216364)

  - CVE-2023-22100 (boo#1216365)

     This is a maintenance release. The following items were fixed and/or added:

  - VMM: Fixed using a debugger inside the guest under certain circumstances
       (bugs #21413 and #21546)

  - VMM: Fixed detection of VT-x being used by other hypervisors (bug #21867)

  - VMM: Introduced additional improvements in Split Lock Detection feature
       of recent Intel CPUs on Linux hosts (bug #20180)

  - GUI: Fixed issue when the nested hardware virtualization setting was not
       displayed in the VM details panel (bug #21707)

  - GUI: Introduced NLS update for Croatian, Indonesian, Italian, Japanese,
       Korean, Dutch and Turkish languages as well as added general
       look-and-feel improvements

  - Devices: Fixed black screen in Windows guests with multiple guest
       screens when 3D is disabled (7.0.10 regression)

  - Devices: Fixed PCI device identifiers for the VirtIO network interface
       (bug #21516)

  - Devices: Fixed VLAN support for the VirtIO network interface (bug #21778)

  - Devices: Fixed loading saved states when a TPM is configured (7.0.10
       regression, bug #21773)

  - Networking: Fixed memory leaks in the VBoxIntNetSwitch process on macOS
       (bug #21752)

  - Networking: Fixed TCP connections with IP addresses ending on .2 when
       the NAT network attachment is used (bug #21513)

  - VRDP: Added general improvements

  - VBoxManage: Added improvements for 'list usbfilters' command

  - Unattended: Added kick start file support for Oracle Linux 8 and Oracle
       Linux 9.

  - Main: Added more Linux OS subtypes

  - Host Services: Fixed Guest Properties service crash under rare
       circumstance

  - Linux Host and Guest: Fixed few 'field-spanning write' kernel warnings
       (bugs #21410 and #21862)

  - Linux Guest Additions: Added more fixes for RHEL 8.9 and 9.3 kernel

  - Linux Guest Additions: Added more fixes for kernel 6.4

  - Linux Guest Additions: Added initial support for OpenSUSE 15.5 kernel

  - Linux Guest Additions: Added initial support for kernels 6.5 and 6.6

  - Linux Guest Additions: Added version reporting for 'rcvboxadd
       status-kernel' and 'rcvboxadd status-user' commands

  - BIOS: Restored support for ISA SCSI HBAs in the BIOS (bug #21736)

  - Convert to systemd-sysusers");

  script_tag(name:"affected", value:"'virtualbox' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-debugsource", rpm:"virtualbox-kmp-debugsource~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~7.0.12_k5.14.21_150400.24.92~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~7.0.12_k5.14.21_150400.24.92~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-debugsource", rpm:"virtualbox-kmp-debugsource~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~7.0.12_k5.14.21_150400.24.92~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default-debuginfo", rpm:"virtualbox-kmp-default-debuginfo~7.0.12_k5.14.21_150400.24.92~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~7.0.12~lp154.2.43.1", rls:"openSUSELeap15.4"))) {
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