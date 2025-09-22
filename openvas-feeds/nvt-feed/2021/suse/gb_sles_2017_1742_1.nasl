# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1742.1");
  script_cve_id("CVE-2017-8309", "CVE-2017-9330");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:50:05 +0000 (Thu, 01 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1742-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1742-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171742-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042938");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SMR5V6EH656GKCNXCGNOXX5MUWUMX5AR/#SMR5V6EH656GKCNXCGNOXX5MUWUMX5AR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:1742-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:

- Page transfer might have allowed PV guest to elevate privilege (XSA-217, bsc#1042882)
- Races in the grant table unmap code allowed for informations leaks and potentially privilege escalation (XSA-218, bsc#1042893)
- Insufficient reference counts during shadow emulation allowed a malicious pair of guest to elevate their privileges to the privileges that XEN runs under (XSA-219, bsc#1042915)
- Missing NULL pointer check in event channel poll allows guests to DoS the host (XSA-221, bsc#1042924)
- Stale P2M mappings due to insufficient error checking allowed malicious guest to leak information or elevate privileges (XSA-222, bsc#1042931)
- Grant table operations mishandled reference counts allowing malicious guests to escape (XSA-224, bsc#1042938)
- CVE-2017-9330: USB OHCI Emulation in qemu allowed local guest OS users to cause a denial of service (infinite loop) by leveraging an incorrect return value (bsc#1042160)
- CVE-2017-8309: Memory leak in the audio/audio.c allowed remote attackers to cause a denial of service (memory consumption) by repeatedly starting and stopping audio capture (bsc#1037243)
- PKRU and BND* leakage between vCPU-s might have leaked information to other guests (XSA-220, bsc#1042923)

These non-security issues were fixed:

- bsc#1027519: Included various upstream patches
- bsc#1035642: Ensure that rpmbuild works");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.2_06~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.2_06~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.2_06~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.2_06~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.2_06~42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.2_06~42.1", rls:"SLES12.0SP2"))) {
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
