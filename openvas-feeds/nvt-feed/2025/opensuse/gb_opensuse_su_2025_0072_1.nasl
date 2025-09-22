# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0072.1");
  script_cve_id("CVE-2025-1378");
  script_tag(name:"creation_date", value:"2025-02-24 04:07:13 +0000 (Mon, 24 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-17 06:15:13 +0000 (Mon, 17 Feb 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0072-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0072-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VMIRZD7QDNUWAIAT76VO5EMCPL7MGFOJ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237250");
  script_xref(name:"URL", value:"https://github.com/radareorg/radare2/releases/tag/5.9.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2' package(s) announced via the openSUSE-SU-2025:0072-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for radare2 fixes the following issues:

- CVE-2025-1378: Fixed memory corruption (boo#1237250)

 [link moved to references]

Update to version 5.8.8:

 For details, check full release notes
 * Faster analysis, type matching, binary parsing (2-4x)
 * Add assembler for riscv and disassemblers for PDP11, Alpha64 and armv7.v35
 * Improved integration with r2frida remote filesystems
 * Cleaning debugger for windows (32 and 64) and macOS makes it more reliable and stable
 * Better build scripts for Windows (add asan and w32 profiles)
 * AES key wrap algorithm support in rahash2
 * Print and convert ternary values back and forth

- Update to 4.5.0
 * Fix build of the onefied shared lib
 * Enable asm.jmpsub by default
 * Fix m68k analysis issues
 * Fix infinite loop bug related to anal.nopskip");

  script_tag(name:"affected", value:"'radare2' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.9.8~bp156.4.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-devel", rpm:"radare2-devel~5.9.8~bp156.4.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-zsh-completion", rpm:"radare2-zsh-completion~5.9.8~bp156.4.6.1", rls:"openSUSELeap15.6"))) {
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
