# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1630.1");
  script_cve_id("CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19581", "CVE-2019-19583", "CVE-2020-0543", "CVE-2020-11739", "CVE-2020-11740", "CVE-2020-11741", "CVE-2020-11742", "CVE-2020-7211");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-30 16:08:03 +0000 (Thu, 30 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1630-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1630-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201630-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172205");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006956.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:1630-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2020-0543: Fixed a side channel attack against special registers which could have resulted in leaking of read values to cores other than the one which called it.
 This attack is known as Special Register Buffer Data Sampling (SRBDS) or 'CrossTalk' (bsc#1172205).
- CVE-2020-11742: Bad continuation handling in GNTTABOP_copy (bsc#1169392).
- CVE-2020-11740, CVE-2020-11741: xen: XSA-313 multiple xenoprof issues (bsc#1168140).
- CVE-2020-11739: Missing memory barriers in read-write unlock paths (bsc#1168142).
- CVE-2019-19583: Fixed improper checks which could have allowed HVM/PVH guest userspace code to crash the guest, leading to a guest denial of service (bsc#1158004 XSA-308).
- CVE-2019-19581: Fixed a potential out of bounds on 32-bit Arm (bsc#1158003 XSA-307).
- CVE-2019-19580: Fixed a privilege escalation where a malicious PV guest administrator could have been able to escalate their privilege to that of the host (bsc#1158006 XSA-310).
- CVE-2019-19579: Fixed a privilege escalation where an untrusted domain with access to a physical device can DMA into host memory (bsc#1157888 XSA-306).
- CVE-2019-19578: Fixed an issue where a malicious or buggy PV guest could have caused hypervisor crash resulting in denial of service affecting the entire host (bsc#1158005 XSA-309).
- CVE-2019-19577: Fixed an issue where a malicious guest administrator could have caused Xen to access data structures while they are being modified leading to a crash (bsc#1158007 XSA-311).
- Xenstored Crashed during VM install (bsc#1167152)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.4_06~3.62.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.4_06~3.62.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.9.4_06~3.62.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.4_06~3.62.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.4_06~3.62.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.4_06~3.62.1", rls:"SLES12.0SP3"))) {
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
