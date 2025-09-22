# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1489");
  script_cve_id("CVE-2015-8374", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8660", "CVE-2015-8746", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8787", "CVE-2015-8812", "CVE-2015-8816", "CVE-2015-8944", "CVE-2015-8953", "CVE-2015-8956", "CVE-2015-8961", "CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2015-8970", "CVE-2015-9004", "CVE-2016-0723");
  script_tag(name:"creation_date", value:"2020-01-23 11:54:59 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1489)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1489");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1489");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1489 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information-leak vulnerability was found in the kernel when it truncated a file to a smaller size which consisted of an inline extent that was compressed. The data between the new file size and the old file size was not discarded and the number of bytes used by the inode were not correctly decremented, which gave the wrong report for callers of the stat(2) syscall. This wasted metadata space and allowed for the truncated data to be leaked, and data corruption or loss to occur. A caller of the clone ioctl could exploit this flaw by using only standard file-system operations without root access to read the truncated data.(CVE-2015-8374)

A flaw was found in the Linux kernel's key management system where it was possible for an attacker to escalate privileges or crash the machine. If a user key gets negatively instantiated, an error code is cached in the payload area. A negatively instantiated key may be then be positively instantiated by updating it with valid data. However, the ->update key type method must be aware that the error code may be there.(CVE-2015-8539)

A NULL pointer dereference flaw was found in the way the Linux kernel's network subsystem handled socket creation with an invalid protocol identifier. A local user could use this flaw to crash the system.(CVE-2015-8543)

An out-of-bounds flaw was found in the kernel, where the length of the sockaddr parameter was not checked in the pptp_bind() and pptp_connect() functions. As a result, more kernel memory was copied out than required, leaking information from the kernel stack (including kernel addresses). A local system user could exploit this flaw to bypass kernel ASLR or leak other information.(CVE-2015-8569)

An out-of-bounds flaw was found in the kernel, where the sco_sock_bind() function (bluetooth/sco) did not check the length of its sockaddr parameter. As a result, more kernel memory was copied out than required, leaking information from the kernel stack (including kernel addresses). A local user could exploit this flaw to bypass kernel ASLR or leak other information.(CVE-2015-8575)

The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application.(CVE-2015-8660)

A NULL pointer dereference flaw was found in the Linux kernel: the NFSv4.2 migration code improperly initialized the kernel structure. A local, authenticated user could use this flaw to cause a panic of the NFS client (denial of service).(CVE-2015-8746)

A race condition flaw was found in the way the Linux kernel's SCTP implementation handled sctp_accept() during the processing of heartbeat timeout events. A remote attacker could use this flaw to prevent further connections to be accepted by the SCTP server running on the system, resulting ... [Please see the references for more information on the vulnerabilities]");

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
