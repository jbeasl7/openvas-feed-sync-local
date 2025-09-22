# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856644");
  script_cve_id("CVE-2022-47952");
  script_tag(name:"creation_date", value:"2024-10-31 05:01:51 +0000 (Thu, 31 Oct 2024)");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-09 15:20:26 +0000 (Mon, 09 Jan 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0342-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OOSMXYJMF3W5N7MDXO2O3PADSGDX4HXP/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206779");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the openSUSE-SU-2024:0342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lxc fixes the following issues:

lxc was updated to 6.0.2:

 The LXC team is pleased to announce the release of LXC 6.0.2!
 This is the second bugfix release for LXC 6.0 which is supported
 until June 2029.

 As usual this bugfix releases focus on stability and hardening.

 * Some of the highlights for this release are:

 - Reduced log level on some common messages
 - Fix compilation error on aarch64

 * Detailed changelog

 - Remove unused function
 - idmap: Lower logging level of newXidmap tools to INFO
 - Exit 0 when there's no error
 - doc: Fix definitions of get_config_path and set_config_path
 - README: Update security contact
 - fix possible clang compile error in AARCH

Update to 6.0.1:

 The LXC team is pleased to announce the release of LXC 6.0.1!
 This is the first bugfix release for LXC 6.0 which is supported
 until June 2029.

 As usual this bugfix releases focus on stability and hardening.

 * Highlights

 - Fixed some build tooling issues
 - Fixed startup failures on system without IPv6 support
 - Updated AppArmor rules to avoid potential warnings

Update to 6.0.0:

 The LXC team is pleased to announce the release of LXC 6.0 LTS!
 This is the result of two years of work since the LXC 5.0 release
 and is the sixth LTS release for the LXC project. This release
 will be supported until June 2029.

 * New multi-call binaryP

 A new tools-multicall=true configuration option can be used to
 produce a single lxc binary which can then have all other
 lxc-XYZ commands be symlinked to.
 This allows for a massive disk space reduction, particularly
 useful for embedded platforms.

 * Add a set_timeout function to the library

 A new set_timeout function is available on the main
 lxc_container struct and allow for setting a global timeout for
 interactions with the LXC monitor.
 Prior to this, there was no timeout, leading to potential
 deadlocks as there's also no way to cancel an monitor request.
 As a result of adding this new symbol to the library, we have
 bumped the liblxc symbol version to 1.8.0.

 * LXC bridge now has IPV6 enabled

 The default lxcbr0 bridge now comes with IPv6 enabled by
 default, using an IPv6 ULA subnet.
 Support for uid/gid selection in lxc-usernsexec
 The lxc-usernsexec tool now has both -u and -g options to
 control what resulting UID and GID (respectively) the user
 wishes to use (defaulting to 0/0).

 * Improvements to lxc-checkconfig

 lxc-checkconfig now only shows the version if lxc-start is
 present (rather than failing).
 Additionally, it's seen a number of other cosmetic improvements
 as well as now listing the maximum number of allowed namespaces
 for every namespace type.

 * Support for squashfs OCI images

 The built-in oci container template can now handle squashfs
 compressed OCI images through the use of atomfs.

 * Switched from systemd's dbus to dbus-1

 LXC now uses libdbus-1 for DBus interactions with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'lxc' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"liblxc-devel", rpm:"liblxc-devel~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1", rpm:"liblxc1~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-bash-completion", rpm:"lxc-bash-completion~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-ja-doc", rpm:"lxc-ja-doc~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-ko-doc", rpm:"lxc-ko-doc~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_cgfs", rpm:"pam_cgfs~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"liblxc-devel", rpm:"liblxc-devel~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1", rpm:"liblxc1~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-bash-completion", rpm:"lxc-bash-completion~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-ja-doc", rpm:"lxc-ja-doc~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-ko-doc", rpm:"lxc-ko-doc~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_cgfs", rpm:"pam_cgfs~6.0.2~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
