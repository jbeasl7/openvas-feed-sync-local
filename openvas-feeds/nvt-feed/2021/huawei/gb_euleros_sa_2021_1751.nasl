# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1751");
  script_cve_id("CVE-2020-0465", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-25639", "CVE-2021-0342", "CVE-2021-20177", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-3178", "CVE-2021-3347", "CVE-2021-3348");
  script_tag(name:"creation_date", value:"2021-04-13 06:16:08 +0000 (Tue, 13 Apr 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:02:01 +0000 (Thu, 04 Feb 2021)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-1751)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1751");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1751");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2021-1751 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer leak can be used to determine the address of the iscsi_transport structure. When an iSCSI transport is registered with the iSCSI subsystem, the transport's handle is available to unprivileged users via the sysfs file system, at /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the show_transport_handle function (in drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the handle. This handle is actually the pointer to an iscsi_transport struct in the kernel module's global variables.(CVE-2021-27363)

An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message.(CVE-2021-27365)

An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is adversely affected by the ability of an unprivileged user to craft Netlink messages.(CVE-2021-27364)

Overlayfs did not properly perform permission checking when copying up files in an overlayfs and could be exploited from within a user namespace, if, for example, unprivileged user namespaces were allowed. It was possible to have a file not readable by an unprivileged user to be copied to a mountpoint controlled by the user, like a removable device. This was introduced in kernel version 4.19 by commit d1d04ef ('ovl: stack file ops'). This was fixed in kernel version 5.8 by commits 56230d9 ('ovl: verify permissions in ovl_path_open()'), 48bd024 ('ovl: switch to mounter creds in readdir') and 05acefb ('ovl: check permission to open real file'). Additionally, commits 130fdbc ('ovl: pass correct flags for opening real directory') and 292f902 ('ovl: call secutiry hook in ovl_real_ioctl()') in kernel 5.8 might also be desired or necessary. These additional commits introduced a regression in overlay mounts within user namespaces which prevented access to files with ownership outside of the user namespace. This regression was mitigated by subsequent commit b6650da ('ovl: do not fail because of O_NOATIMEi') in kernel 5.11.(CVE-2020-16120)

A flaw was found in the Linux kernel's implementation of string matching within a packet. A privileged user (with root or CAP_NET_ADMIN) when inserting iptables rules could insert a rule which can panic the system.(CVE-2021-20177)

fs/nfsd/nfs3xdr.c in the Linux kernel through 5.10.8, when there is an NFS export of a subdirectory of a filesystem, allows remote attackers to traverse to other parts of the filesystem via READDIRPLUS. NOTE: some parties argue that such a subdirectory export is not intended to prevent this attack, see also the exports(5) no_subtree_check default behavior.(CVE-2021-3178)

nbd_add_socket in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h425.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h425.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h425.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.18.0~147.5.1.6.h425.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
