# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122036");
  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:01 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2011-1532)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1532");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1532.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kexec-tools' package(s) announced via the ELSA-2011-1532 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.0.0-209.0.1.el6]
- Make sure '--allow-missing' is effective by adding to MKDUMPRD_ARGS in
 kdump.sysconfig, kdump.sysconfig.i386, and kdump.sysconfig.x86_64 [12590865] [11678808]

[2.0.0-209]
- Improve debugfs mounting code, from Dave Young.
 Resolve bug 748748.

[2.0.0-208]
- Search DUP firmware directory too, from Caspar Zhang.
 Resolve bug 747233.

[2.0.0-207]
- Don't run kdump service on s390x, from Caspar Zhang.
 Resolve bug 746207.

[2.0.0-206]
- Fix some security flaws, resolve bug 743165.

[2.0.0-205]
- Fix a scriptlet failure in fence-agents, resolve bug 739050.

[2.0.0-204]
- Add new config 'force_rebuild', resolve bug 598067.

[2.0.0-203]
- Warn users to use maxcpus=1 instead of nr_cpus=1 for older
 kernels, resolve bug 727892.

[2.0.0-202]
- Pass 'noefi acpi_rsdp=X' to the second kernel, resolve bug 681796.

[2.0.0-201]
- Include patch 602 for rawbuild, resolve bug 708503.

[2.0.0-200]
- Remove the warning for reserved memory on x86, resolve BZ 731394.

[2.0.0-199]
- Add debug_mem_level debugging option, from Jan Stancek.
 Resolve Bug 734528.

[2.0.0-198]
- Fix the error message on /etc/cluster_iface,
 resolve bug 731236. From Ryan O'Hara.

[2.0.0-197]
- Add coordination between kdump and cluster fencing for long
 kernel panic dumps, resolve bug 585332. From Ryan O'Hara.

[2.0.0-196]
- Use nr_cpus=1 instead of maxcpus=1 on x86, resolve Bug 725484.

[2.0.0-195]
- Fix segfault on ppc machine with 1TB memory, resolve Bug 709441.

[2.0.0-194]
- Specify kernel version for every modprobe, resolve Bug 719105.

[2.0.0-193]
- Don't handle raid device specially, resolve Bug 707805.

[2.0.0-192]
- Read mdadm.conf correctly, resolve Bug 707805.

[2.0.0-191]
- Use makedumpfile as default core_collector for ssh dump.
 Resolve Bug 693025.

[2.0.0-190]
- Revert the previous patch, resolve Bug 701339.

[2.0.0-189]
- Disable THP in kdump kernel, resolve Bug 701339.");

  script_tag(name:"affected", value:"'kexec-tools' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kexec-tools", rpm:"kexec-tools~2.0.0~209.0.1.el6", rls:"OracleLinux6"))) {
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
