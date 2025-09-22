# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885752");
  script_cve_id("CVE-2024-23301");
  script_tag(name:"creation_date", value:"2024-02-21 02:06:36 +0000 (Wed, 21 Feb 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-22 19:21:26 +0000 (Mon, 22 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-a2f6e5ddb8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a2f6e5ddb8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a2f6e5ddb8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215778");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254871");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258397");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rear' package(s) announced via the FEDORA-2024-a2f6e5ddb8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Fri Feb 9 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-8
- Sync with patches in CentOS Stream 9 (kudos to @pcahyna!) chronologically
 from the latest:
 - Resolve libs for executable links in COPY_AS_IS, PR 3073
 - Skip invalid disk drives when saving layout PR 3047
 - Do not delete NetBackup logs in case of errors and save
 /usr/openv/netbackup/logs to the restored system after a successful recovery
 - Add /usr/openv/var to COPY_AS_IS_NBU, fixes an issue seen
 with NetBackup 10.2.0.1
 - Support saving and restoring hybrid BIOS/UEFI bootloader, PRs 3145 3136
* Thu Feb 8 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-7
- do not generate /etc/rear/os.conf during build
* Wed Feb 7 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-6
- copy the console= kernel arguments from the original system
* Tue Feb 6 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-5
- replace dhcp-client with dhcpcd (rhbz#2247060)
* Tue Feb 6 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-4
- make initrd accessible only by root (CVE-2024-23301)
* Tue Feb 6 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-3
- fix unusable recovery with newer systemd (rbhz#2254871)
* Mon Feb 5 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-2
- migrate to SPDX license format
- properly use %license and %doc macros
- use https in URLs
* Fri Feb 2 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.7-1
- rebase to version 2.7 (rhbz#2215778)
- drop obsolete patches
- rebase remaining patches
* Fri Feb 2 2024 Lukas Zaoral <lzaoral@redhat.com> - 2.6-14
- Sync with patches in CentOS Stream 9 (kudos to @pcahyna!) chronologically
 from the latest:
 - Backport PR 3061 to save LVM pool metadata volume size in disk layout
 and restore it
 - Backport PR 3058 to skip useless xfs mount options when mounting
 during recovery, prevents mount errors like 'logbuf size must be greater
 than or equal to log stripe size'
 - Add patch to force removal of lvmdevices, prevents LVM problems after
 restoring to different disks/cloning. Upstream PR 3043
 - Add patch to start rsyslog and include NBU systemd units
 - Apply PR 3027 to ensure correct creation of the rescue environment
 when a file is shrinking while being read
 - Backport PR 2774 to increase USB_UEFI_PART_SIZE to 1024 MiB
 - Apply upstream patch for temp dir usage with LUKS to ensure
 that during recovery an encrypted disk can be unlocked using a keyfile
 - Backport upstream PR 3031: Secure Boot support for OUTPUT=USB
 - Correct a mistake done when backporting PR 2691
 - Backport PR2943 to fix s390x dasd formatting
 - Require s390utils-{core,base} on s390x
 - Apply PR2903 to protect against colons in pvdisplay output
 - Apply PR2873 to fix initrd regeneration on s390x
 - Apply PR2431 to migrate XFS configuration files
 - Exclude /etc/lvm/devices from the rescue system to work around a segfault
 in lvm pvcreate
 - Avoid stderr message about irrelevant broken links
 - Changes for NetBackup (NBU) 9.x support
 - ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'rear' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"rear", rpm:"rear~2.7~8.fc39", rls:"FC39"))) {
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
