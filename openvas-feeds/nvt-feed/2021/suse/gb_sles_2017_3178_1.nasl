# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3178.1");
  script_cve_id("CVE-2017-15289", "CVE-2017-15597");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-18 16:11:55 +0000 (Sat, 18 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3178-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173178-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068191");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003466.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:3178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen to version 4.7.4 (bsc#1027519) fixes several issues.

This new feature was added:

- Support migration of HVM domains larger than 1 TB

These security issues were fixed:

- bsc#1068187: Failure to recognize errors in the Populate on Demand (PoD) code
 allowed for DoS (XSA-246)
- bsc#1068191: Missing p2m error checking in PoD code allowed unprivileged guests
 to retain a writable mapping of freed memory leading to information leaks,
 privilege escalation or DoS (XSA-247).
- CVE-2017-15289: The mode4and5 write functions allowed local OS guest privileged
 users to cause a denial of service (out-of-bounds write access and Qemu process
 crash) via vectors related to dst calculation (bsc#1063123)
- CVE-2017-15597: A grant copy operation being done on a grant of a dying domain
 allowed a malicious guest administrator to corrupt hypervisor memory, allowing
 for DoS or potentially privilege escalation and information leaks (bsc#1061075).

This non-security issue was fixed:

- bsc#1055047: Fixed --initrd-inject option in virt-install");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.4_02~43.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.4_02~43.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.4_02~43.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.4_02~43.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.4_02~43.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.4_02~43.21.1", rls:"SLES12.0SP2"))) {
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
