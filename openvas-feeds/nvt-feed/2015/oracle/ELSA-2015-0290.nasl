# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123167");
  script_cve_id("CVE-2014-3690", "CVE-2014-3940", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-8086", "CVE-2014-8160", "CVE-2014-8172", "CVE-2014-8173", "CVE-2014-8709", "CVE-2014-8884", "CVE-2015-0274");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:13 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:17:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-0290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0290");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0290.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-0290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-229]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-229]
- [net] rtnetlink: allow to register ops without ops->setup set (Jiri Benc) [1186492]

[3.10.0-228]
- [fs] NFSv4.1: Fix an Oops in nfs41_walk_client_list (Steve Dickson) [1185784]
- [misc] redhat: don't suppress Revert patches from changelog (Jarod Wilson) [1187353]
- [infiniband] Revert: ipoib: Consolidate rtnl_lock tasks in workqueue (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: Make the carrier_on_task race aware (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: fix MCAST_FLAG_BUSY usage (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: fix mcast_dev_flush/mcast_restart_task race (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: change init sequence ordering (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: Use dedicated workqueues per interface (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: Make ipoib_mcast_stop_thread flush the workqueue (Doug Ledford) [1179740]
- [infiniband] Revert: ipoib: No longer use flush as a parameter (Doug Ledford) [1179740]
- [fs] fix deadlock in cifs_ioctl_clone() (Sachin Prabhu) [1183980]
- [md] dm-cache: fix missing ERR_PTR returns and handling (Mike Snitzer) [1182665]
- [fs] cifs: fix regression in cifs_create_mf_symlink() (Sachin Prabhu) [1186324]
- [net] ipv4: try to cache dst_entries which would cause a redirect (Hannes Frederic Sowa) [1181819]
- [fs] coredump: add new P variable in core_pattern (Jiri Olsa) [1186360]
- [drm] fix fb-helper vs MST dangling connector ptrs (Rob Clark) [1184968]
- [net] bridge: Program port vlan filters only if filtering is enabled in bridge (Vlad Yasevich) [1183958]
- [fs] cifs: Complete oplock break jobs before closing file handle (Sachin Prabhu) [1177215]
- [fs] LOCKD: Fix a race when initialising nlmsvc_timeout (Benjamin Coddington) [1144982]
- [scsi] hpsa: add in P840ar controller model name (Joseph Szczypek) [1185467]
- [scsi] hpsa: add in gen9 controller model names (Joseph Szczypek) [1185467]

[3.10.0-227]
- [fs] ext4: fix overwrite race condition (Jacob Tanenbaum) [1152607] {CVE-2014-8086}
- [media] ttusb-dec: buffer overflow in ioctl (Alexander Gordeev) [1167116] {CVE-2014-8884}
- [drm] i915: demote opregion excessive timeout WARN_ONCE to DRM_INFO_ONCE (Rob Clark) [1145627]
- [md] Revert: raid56: Don't perform reads to support writes until stripe is ready (Jes Sorensen) [1153796]
- [md] Revert: raid5: avoid livelock caused by non-aligned writes (Jes Sorensen) [1153796]
- [drm] i915: further quiet i915 (Rob Clark) [1163074]
- [scsi] megaraid_sas: endianness related bug fixes and code optimization (Tomas Henzl) [1179748]
- [s390] crypto: kernel oops at insmod of the z90crypt device driver (Hendrik Brueckner) [1172136]
- [drm] mgag200: Add command line option to specify preferred depth (Dave Airlie) [1044555]
- [drm] mgag200: Consolidate depth/bpp handling (Dave Airlie) [1044555]
- [fs] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.el7", rls:"OracleLinux7"))) {
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
