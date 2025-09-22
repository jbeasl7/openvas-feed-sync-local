# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856991");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2023-52752", "CVE-2024-35949", "CVE-2024-36979", "CVE-2024-40909", "CVE-2024-40920", "CVE-2024-40921", "CVE-2024-40954", "CVE-2024-41057", "CVE-2024-42133", "CVE-2024-43861", "CVE-2024-50264");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-21 19:28:21 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"creation_date", value:"2025-01-28 05:02:34 +0000 (Tue, 28 Jan 2025)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 2 for SLE 15 SP6) (SUSE-SU-2025:0262-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0262-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7UOXGGREOSJ53ORKFSFCDZDAAVNXG52J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 2 for SLE 15 SP6)'
  package(s) announced via the SUSE-SU-2025:0262-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 6.4.0-150600_23_14 fixes several issues.

  The following security issues were fixed:

    * CVE-2024-40921: net: bridge: mst: pass vlan group directly to
      br_mst_vlan_set_state (bsc#1227784).
    * CVE-2024-40920: net: bridge: mst: fix suspicious rcu usage in
      br_mst_set_state (bsc#1227781).
    * CVE-2024-36979: net: bridge: mst: fix vlan use-after-free (bsc#1227369).
    * CVE-2024-41057: cachefiles: fix slab-use-after-free in
      cachefiles_withdraw_cookie() (bsc#1229275).
    * CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer
      occurring in vsk->trans (bsc#1233712).
    * CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229553).
    * CVE-2024-42133: Bluetooth: Ignore too large handle values in BIG
      (bsc#1231419).
    * CVE-2024-35949: btrfs: make sure that WRITTEN is set on all metadata blocks
      (bsc#1229273).
    * CVE-2023-52752: smb: client: fix use-after-free bug in
      cifs_debug_data_proc_show() (bsc#1225819).
    * CVE-2024-40954: net: do not leave a dangling sk pointer, when socket
      creation fails (bsc#1227808)
    * CVE-2024-40909: bpf: Fix a potential use-after-free in bpf_link_free()
      (bsc#1228349).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 2 for SLE 15 SP6)' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_4_0-150600_23_14-default-debuginfo-7", rpm:"kernel-livepatch-6_4_0-150600_23_14-default-debuginfo-7~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_4_0-150600_23_14-default-7", rpm:"kernel-livepatch-6_4_0-150600_23_14-default-7~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP6_Update_2-debugsource-7", rpm:"kernel-livepatch-SLE15-SP6_Update_2-debugsource-7~150600.13.6.1", rls:"openSUSELeap15.6"))) {
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
