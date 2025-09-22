# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123976");
  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2012-0152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0152");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0152.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kexec-tools' package(s) announced via the ELSA-2012-0152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.102pre-154.0.3]
- mkdumprd.orig get packed, remove it.

[1.102pre-154.0.2]
- fix mounting root fs on labeled disk (Maxim Uvarov) [orabug: 13709374]

[1.102pre-154.0.1]
Merge following patches from mkinitrd:
- mkinitrd-fix-san-boot.patch
- mkinitrd-fix-shared-lib-library-path.patch
- mkinitrd-5.1.19.6-libfirmware-subdir-include.patch
- mkinitrd-fix-setquiet-for-non-verbose.patch
- add-option-to-forceload-multipath.patch
- Update kexec-kdump-howto.txt with Oracle references
- Add mkdumprd load firmware support [orabug 10432768]
- Updated makedumpfile to el6 version (Herbert van den Bergh) [orabug 10088607]
- Merged UEK modification,Updated Source1 kdump.init
 Added --allow-missing for rebuilding kdump_initrd
- Updated kexec-kdump-howto.txt with Oracle references

[1.102pre-154]
- Add xfs support, resolve bug 668706.

[1.102pre-153]
- Avoid recursive directory deletion when unmount failed, from Cai Qian.
 Resolve bug 781907.

[1.102pre-152]
- Replace sed with awk in interface-mapping code,
 resolve bug 765702.

[1.102pre-151]
- Set pipefail to catch errors in a pipe, resolve bug 761336.

[1.102pre-150]
- Remove the restriction for Xen HVM guests, resolve bug 743217.

[1.102pre-149]
- Honor the resettable flag, resolve bug 761048.

[1.102pre-148]
- Revert the patch in -144, resolve bug 755781. From Cai Qian.

[1.102pre-147]
- Poll every ifcfg file to get bridge members, resolve bug 760844.

[1.102pre-146]
- Don't add default gateway when there is none. Resolve bug 759006.

[1.102pre-145]
- Bypass blacklist option for target checking. Resolve bug 690678.

[1.102pre-144]
- Change the default core_collector for raw dump to makedumpfile.
 Resolve bug 755781.

[1.102pre-143]
- Support static route. Resolve bug 715531.

[1.102pre-142]
- Fix some security flaws. Resolve bug 743163.

[1.102pre-141]
- Remove two unused patches.

[1.102pre-140]
- Fix link_delay regression since -135, resolve bug 753684.

[1.102pre-139]
- Improve debugfs mounting code, from Dave Young. Resolve bug 748749.

[1.102pre-138]
- Backport blacklist option. Resolve bug 690678.

[1.102pre-137]
- Fix link_delay handling code. Resolve bug 682359.

[1.102pre-136]
- Add /etc/fstab into initrd, resolve Bug 748319.

[1.102pre-135]
- Support dump over vlan tagged bond. Resolve bug 682359.

[1.102pre-134]
- Fix two trivial bugs, Bug 709622 and Bug 662530.

[1.102pre-133]
- Support software iscsi as dump target, from Vivek Goyal.
 Resolve bug 719384.

[1.102pre-132]
- Add the missing part of the previous patch. Resolve bug 696547.

[1.102pre-131]
- Get the backup memory region dynamically. Resolve bug 678308.

[1.102pre-130]
- Add ext4 module. Resolve bug 667791.

[1.102pre-129]
- Updating release to force brew rebuild

[1.102pre-128]
- Check fsck.ext4 binary before include it. Resolve bug 667791.

[1.102pre-127]
- Add ext4 support, from Dave Maley. Resolve bug 667791.");

  script_tag(name:"affected", value:"'kexec-tools' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kexec-tools", rpm:"kexec-tools~1.102pre~154.0.3.el5", rls:"OracleLinux5"))) {
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
