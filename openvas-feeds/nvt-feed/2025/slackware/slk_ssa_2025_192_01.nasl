# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.192.01");
  script_cve_id("CVE-2024-36348", "CVE-2024-36349", "CVE-2024-36350", "CVE-2024-36357");
  script_tag(name:"creation_date", value:"2025-07-14 04:27:04 +0000 (Mon, 14 Jul 2025)");
  script_version("2025-07-14T05:43:40+0000");
  script_tag(name:"last_modification", value:"2025-07-14 05:43:40 +0000 (Mon, 14 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-192-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2025-192-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.758387");
  script_xref(name:"URL", value:"https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-36348");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-36349");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-36350");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-36357");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2025-192-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/kernel-firmware-20250708_99d64b4-noarch-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-generic-5.15.187-i586-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-generic-smp-5.15.187_smp-i686-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-headers-5.15.187_smp-x86-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-huge-5.15.187-i586-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-huge-smp-5.15.187_smp-i686-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-modules-5.15.187-i586-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-modules-smp-5.15.187_smp-i686-1.txz: Upgraded.
patches/packages/linux-5.15.187/kernel-source-5.15.187_smp-noarch-1.txz: Upgraded.
 These updates fix various bugs and security issues.
 Included is a mitigation for the AMD Transient Scheduler Attacks that have
 been in the news lately.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"20250708_99d64b4-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.187-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"5.15.187-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"5.15.187_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.187-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"5.15.187_smp-x86-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.187-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"5.15.187-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"5.15.187_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.187-i586-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"5.15.187-x86_64-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"5.15.187_smp-i686-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.187-noarch-1", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"5.15.187_smp-noarch-1", rls:"SLK15.0"))) {
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
