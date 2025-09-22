# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0128.1");
  script_cve_id("CVE-2023-1786");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-08 18:38:50 +0000 (Mon, 08 May 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4|openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0128-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240128-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216011");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-January/033759.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cloud-init' package(s) announced via the SUSE-SU-2024:0128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cloud-init contains the following fixes:

- Move fdupes call back to %install.(bsc#1214169)

- Update to version 23.3. (bsc#1216011)
 * (bsc#1215794)
 * (bsc#1215740)
 * (bsc#1216007)
 + Bump pycloudlib to 1!5.1.0 for ec2 mantic daily image support (#4390)
 + Fix cc_keyboard in mantic (LP: #2030788)
 + ec2: initialize get_instance_userdata return value to bytes (#4387)
 [Noah Meyerhans]
 + cc_users_groups: Add doas/opendoas support (#4363) [dermotbradley]
 + Fix pip-managed ansible
 + status: treat SubState=running and MainPID=0 as service exited
 + azure/imds: increase read-timeout to 30s (#4372) [Chris Patterson]
 + collect-logs fix memory usage (SC-1590) (#4289)
 [Alec Warren] (LP: #1980150)
 + cc_mounts: Use fallocate to create swapfile on btrfs (#4369)
 + Undocument nocloud-net (#4318)
 + feat(akamai): add akamai to settings.py and apport.py (#4370)
 + read-version: fallback to get_version when git describe fails (#4366)
 + apt: fix cloud-init status --wait blocking on systemd v 253 (#4364)
 + integration tests: Pass username to pycloudlib (#4324)
 + Bump pycloudlib to 1!5.1.0 (#4353)
 + cloud.cfg.tmpl: reorganise, minimise/reduce duplication (#4272)
 [dermotbradley]
 + analyze: fix (unexpected) timestamp parsing (#4347) [Mina Galic]
 + cc_growpart: fix tests to run on FreeBSD (#4351) [Mina Galic]
 + subp: Fix spurious test failure on FreeBSD (#4355) [Mina Galic]
 + cmd/clean: fix tests on non-Linux platforms (#4352) [Mina Galic]
 + util: Fix get_proc_ppid() on non-Linux systems (#4348) [Mina Galic]
 + cc_wireguard: make tests pass on FreeBSD (#4346) [Mina Galic]
 + unittests: fix breakage in test_read_cfg_paths_fetches_cached_datasource
 (#4328) [Ani Sinha]
 + Fix test_tools.py collection (#4315)
 + cc_keyboard: add Alpine support (#4278) [dermotbradley]
 + Flake8 fixes (#4340) [Robert Schweikert]
 + cc_mounts: Fix swapfile not working on btrfs (#4319) [Wang Jian Bing ] (LP: #1884127)
 + ds-identify/CloudStack: $DS_MAYBE if vm running on vmware/xen (#4281)
 [Wei Zhou]
 + ec2: Support double encoded userdata (#4275) [Noah Meyerhans]
 + cc_mounts: xfs is a Linux only FS (#4334) [Mina Galic]
 + tests/net: fix TestGetInterfaces' mock coverage for get_master (#4336)
 [Chris Patterson]
 + change openEuler to openeuler and fix some bugs in openEuler (#4317)
 [sxt1001]
 + Replace flake8 with ruff (#4314)
 + NM renderer: set default IPv6 addr-gen-mode for all interfaces to eui64
 (#4291) [Ani Sinha]
 + cc_ssh_import_id: add Alpine support and add doas support (#4277)
 [dermotbradley]
 + sudoers not idempotent (SC-1589) (#4296) [Alec Warren] (LP: #1998539)
 + Added support for Akamai Connected Cloud (formerly Linode) (#4167)
 [Will Smith]
 + Fix reference before assignment (#4292)
 + Overhaul module reference page (#4237) [Sally]
 + replaced spaces with commas for setting passenv (#4269) [Alec Warren]
 + DS VMware: modify a few log level (#4284) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cloud-init' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cloud-init", rpm:"cloud-init~23.3~150100.8.71.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloud-init-config-suse", rpm:"cloud-init-config-suse~23.3~150100.8.71.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloud-init-doc", rpm:"cloud-init-doc~23.3~150100.8.71.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"cloud-init", rpm:"cloud-init~23.3~150100.8.71.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloud-init-config-suse", rpm:"cloud-init-config-suse~23.3~150100.8.71.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloud-init-doc", rpm:"cloud-init-doc~23.3~150100.8.71.1", rls:"openSUSELeap15.5"))) {
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
