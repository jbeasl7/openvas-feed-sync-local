# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3191.1");
  script_cve_id("CVE-2019-0816");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-10 18:11:13 +0000 (Wed, 10 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3191-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3191-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193191-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cloud-init' package(s) announced via the SUSE-SU-2019:3191-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cloud-init fixes the following issues:

Security issue fixed:
CVE-2019-0816: Fixed the unnecessary extra ssh keys that were added to
 authorized_keys (bsc#1129124).

Non-security issues fixed:
Add cloud-init-renderer-detect.patch (bsc#1154092, bsc#1142988)
 + Short curcuit the conditional for identifying the sysconfig renderer.
 If we find ifup/ifdown accept the renderer as available.
Add cloud-init-break-resolv-symlink.patch (bsc#1151488)
 + If /etc/resolv.conf is a symlink break it. This will avoid netconfig
 from clobbering the changes cloud-init applied.
Update to cloud-init 19.2 (bsc#1099358)
 + Remove, included upstream
 - cloud-init-detect-nova.diff
 - cloud-init-add-static-routes.diff
 + net: add rfc3442 (classless static routes) to EphemeralDHCP (LP:
 #1821102)
 + templates/ntp.conf.debian.tmpl: fix missing newline for pools (LP:
 #1836598)
 + Support netplan renderer in Arch Linux [Conrad Hoffmann]
 + Fix typo in publicly viewable documentation. [David Medberry]
 + Add a cdrom size checker for OVF ds to ds-identify [Pengpeng Sun] (LP:
 #1806701)
 + VMWare: Trigger the post customization script via cc_scripts module.
 [Xiaofeng Wang] (LP: #1833192)
 + Cloud-init analyze module: Added ability to analyze boot events. [Sam
 Gilson]
 + Update debian eni network configuration location, retain Ubuntu
 setting [Janos Lenart]
 + net: skip bond interfaces in get_interfaces [Stanislav Makar] (LP:
 #1812857)
 + Fix a couple of issues raised by a coverity scan
 + Add missing dsname for Hetzner Cloud datasource [Markus Schade]
 + doc: indicate that netplan is default in Ubuntu now
 + azure: add region and AZ properties from imds compute location metadata
 + sysconfig: support more bonding options [Penghui Liao]
 + cloud-init-generator: use libexec path to ds-identify on redhat
 systems (LP: #1833264)
 + tools/build-on-freebsd: update to python3 [GonAfA(c)ri Le Bouder]
 + Allow identification of OpenStack by Asset Tag [Mark T. Voelker] (LP:
 #1669875)
 + Fix spelling error making 'an Ubuntu' consistent. [Brian Murray]
 + run-container: centos: comment out the repo mirrorlist [Paride
 Legovini]
 + netplan: update netplan key mappings for gratuitous-arp (LP: #1827238)
 + freebsd: fix the name of cloudcfg VARIANT [GonAfA(c)ri Le Bouder]
 + freebsd: ability to grow root file system [GonAfA(c)ri Le Bouder]
 + freebsd: NoCloud data source support [GonAfA(c)ri Le Bouder] (LP: #1645824)
 + Azure: Return static fallback address as if failed to find endpoint
 [Jason Zions (MSFT)]
Follow up to update cloud-init-trigger-udev.patch (bsc#1144363)

Update to version 19.1 (bsc#1136440, bsc#1129124)");

  script_tag(name:"affected", value:"'cloud-init' package(s) on SUSE CaaS Platform 3.0, SUSE Linux Enterprise Module for Public Cloud 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"cloud-init", rpm:"cloud-init~19.2~37.33.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloud-init-config-suse", rpm:"cloud-init-config-suse~19.2~37.33.1", rls:"SLES12.0"))) {
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
