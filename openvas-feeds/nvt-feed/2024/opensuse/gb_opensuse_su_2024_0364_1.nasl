# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856714");
  script_cve_id("CVE-2024-21248", "CVE-2024-21259", "CVE-2024-21263", "CVE-2024-21273");
  script_tag(name:"creation_date", value:"2024-11-11 05:00:28 +0000 (Mon, 11 Nov 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:16 +0000 (Tue, 15 Oct 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0364-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0364-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ELCE6LNULD7SDN6FX3HW5773W3KTCWXS/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231738");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox' package(s) announced via the openSUSE-SU-2024:0364-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

Update to release 7.1.4:

* NAT: Fixed DHCP problems with certain guests when domain is
 empty
* VMSVGA: Improved flickering, black screen and other screen
 update issues with recent Linux kernels
* Linux Guest Additions: Introduce initial support for kernel 6.12
* EFI: Added missing LsiLogic MPT SCSI driver again to fix
 booting from devices attached to this device if the EFI
 firmware is used (7.1.0 regression)
* EFI: Restored broken network boot support (7.1.0 regression)
* Adressed CVE-2024-21248 [boo#1231735],
 CVE-2024-21273 [boo#1231736], CVE-2024-21259 [boo#1231737],
 CVE-2024-21263 [boo#1231738]

- Make the Extension Pack work with our compiler flags and RT_NOEXCEPT choices. [boo#1231225]

Update to release 7.1:

* The GUI now offers a selection between Basic and Experienced
 user level with reduced or full UI functionality.
* VRDE: If user does not set up TLS with custom certificates,
 enable it with self-signed certificate, including issuing a
 new one before the old one expires
* NAT: New engine with IPv6 support.
* Linux host and guest: Added Wayland support for Clipboard
 sharing.

- Changed license from Gpl-2.0 to Gpl-3.0

Version bump to VirtualBox 7.0.20 (released July 16 2024 by Oracle))

This is a maintenance release. The following items were fixed and/or added:

- TPM: Fixed errors appearing the event viewer with Windows guests
- macOS Hosts: Fixed passing USB devices to the VM (bug #21218)
- Audio: Fixed recording with HDA emulation after newer Windows 10 / 11 guests got rebooted
- USB: Fixed a deadlock in OHCI triggered when saving the current state of a VM or taking a snapshot (bug #22059)
- Linux Guest and Host: Introduced initial support for OpenSuse 15.6 kernel
- Linux Guest and Host: Introduced initial support for RHEL 9.5 kernel (bug #22099)
- Guest Additions: Shared Clipboard: Fixed issue when extra new lines were pasted when copying text between Win and X11 (bug #21716)
- UEFI Secure Boot: Add new Microsoft certificates to list for new VMs");

  script_tag(name:"affected", value:"'virtualbox' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"kbuild", rpm:"kbuild~0.1.9998+svn3613~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kmp-default", rpm:"virtualbox-kmp-default~7.1.4_k6.4.0_150600.23.25~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~7.1.4~lp156.2.4.1", rls:"openSUSELeap15.6"))) {
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
