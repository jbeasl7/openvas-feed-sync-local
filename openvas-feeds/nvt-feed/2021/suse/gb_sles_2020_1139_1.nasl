# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1139.1");
  script_cve_id("CVE-2020-11739", "CVE-2020-11740", "CVE-2020-11741", "CVE-2020-11742", "CVE-2020-11743", "CVE-2020-7211");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-30 16:08:03 +0000 (Thu, 30 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1139-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201139-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169392");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-April/006757.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:1139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen to version 4.12.2 fixes the following issues:

Security issues fixed:

- CVE-2020-11742: Bad continuation handling in GNTTABOP_copy (bsc#1169392).
- CVE-2020-11740, CVE-2020-11741: xen: XSA-313 multiple xenoprof issues (bsc#1168140).
- CVE-2020-11739: Missing memory barriers in read-write unlock paths (bsc#1168142).
- CVE-2020-11743: Bad error path in GNTTABOP_map_grant (bsc#1168143).
- CVE-2020-7211: Fixed potential directory traversal using relative paths via
 tftp server on Windows host (bsc#1161181).
- arm: a CPU may speculate past the ERET instruction (bsc#1160932).

Non-security issues fixed:

- Xenstored Crashed during VM install (bsc#1167152)
- DomU hang: soft lockup CPU #0 stuck under high load (bsc#1165206, bsc#1134506)
- Update API compatibility versions, fixes issues for libvirt. (bsc#1167007, bsc#1157490)
- aacraid blocks xen commands (bsc#1155200)
- Problems Booting Fedora31 VM on sles15 sp1 Xen Dom0 (bsc#1162040).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.12.2_04~3.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.12.2_04~3.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.12.2_04~3.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.12.2_04~3.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.12.2_04~3.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.12.2_04~3.11.1", rls:"SLES12.0SP5"))) {
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
