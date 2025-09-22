# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1504");
  script_cve_id("CVE-2017-7472", "CVE-2017-7487", "CVE-2017-7495", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7616", "CVE-2017-7645", "CVE-2017-7895", "CVE-2017-8797", "CVE-2017-8824", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242", "CVE-2017-9605", "CVE-2018-1000004", "CVE-2018-10021", "CVE-2018-10087");
  script_tag(name:"creation_date", value:"2020-01-23 11:58:47 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-11 14:19:16 +0000 (Thu, 11 May 2017)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1504");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1504");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1504 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the Linux kernel where the keyctl_set_reqkey_keyring() function leaks the thread keyring. This allows an unprivileged local user to exhaust kernel memory and thus cause a DoS.(CVE-2017-7472)

A reference counter leak in Linux kernel in ipxitf_ioctl function was found which results in a use after free vulnerability that's triggerable from unprivileged userspace when IPX interface is configured.(CVE-2017-7487)

A vulnerability was found in the Linux kernel where filesystems mounted with data=ordered mode may allow an attacker to read stale data from recently allocated blocks in new files after a system 'reset' by abusing ext4 mechanics of delayed allocation.(CVE-2017-7495)

A race condition was found in the Linux kernel, present since v3.14-rc1 through v4.12. The race happens between threads of inotify_handle_event() and vfs_rename() while running the rename operation against the same file. As a result of the race the next slab data or the slab's free list pointer can be corrupted with attacker-controlled data, which may lead to the privilege escalation.(CVE-2017-7533)

Kernel memory corruption due to a buffer overflow was found in brcmf_cfg80211_mgmt_tx() function in Linux kernels from v3.9-rc1 to v4.13-rc1. The vulnerability can be triggered by sending a crafted NL80211_CMD_FRAME packet via netlink. This flaw is unlikely to be triggered remotely as certain userspace code is needed for this. An unprivileged local user could use this flaw to induce kernel memory corruption on the system, leading to a crash. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although it is unlikely.(CVE-2017-7541)

An integer overflow vulnerability in ip6_find_1stfragopt() function was found. A local attacker that has privileges (of CAP_NET_RAW) to open raw socket can cause an infinite loop inside the ip6_find_1stfragopt() function.(CVE-2017-7542)

Incorrect error handling in the set_mempolicy() and mbind() compat syscalls in 'mm/mempolicy.c' in the Linux kernel allows local users to obtain sensitive information from uninitialized stack data by triggering failure of a certain bitmap operation.(CVE-2017-7616)

The NFS2/3 RPC client could send long arguments to the NFS server. These encoded arguments are stored in an array of memory pages, and accessed using pointer variables. Arbitrarily long arguments could make these pointers point outside the array and cause an out-of-bounds memory access. A remote user or program could use this flaw to crash the kernel, resulting in denial of service.(CVE-2017-7645)

The NFSv2 and NFSv3 server implementations in the Linux kernel through 4.10.13 lacked certain checks for the end of a buffer. A remote attacker could trigger a pointer-arithmetic error or possibly cause other unspecified impacts using crafted requests related to fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c.(CVE-2017-7895)

It was found that ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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
