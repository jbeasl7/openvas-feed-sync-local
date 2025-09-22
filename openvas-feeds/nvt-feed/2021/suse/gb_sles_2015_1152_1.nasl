# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1152.1");
  script_cve_id("CVE-2013-2016", "CVE-2013-4344", "CVE-2013-4541", "CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0150", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-2894", "CVE-2014-3461", "CVE-2015-1779", "CVE-2015-3209", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-15 16:17:38 +0000 (Fri, 15 Jan 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1152-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151152-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/817593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932770");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-June/001465.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2015:1152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kvm has been updated to fix issues in the embedded qemu:

 *

 CVE-2014-0223: An integer overflow flaw was found in the QEMU block
 driver for QCOW version 1 disk images. A user able to alter the QEMU
 disk image files loaded by a guest could have used this flaw to
 corrupt QEMU process memory on the host, which could potentially have
 resulted in arbitrary code execution on the host with the privileges
 of the QEMU process.

 *

 CVE-2014-3461: A user able to alter the savevm data (either on the
 disk or over the wire during migration) could have used this flaw to
 to corrupt QEMU process memory on the (destination) host, which could
 have potentially resulted in arbitrary code execution on the host
 with the privileges of the QEMU process.

 *

 CVE-2014-0222: An integer overflow flaw was found in the QEMU block
 driver for QCOW version 1 disk images. A user able to alter the QEMU
 disk image files loaded by a guest could have used this flaw to
 corrupt QEMU process memory on the host, which could have potentially
 resulted in arbitrary code execution on the host with the privileges
 of the QEMU process.

Non-security bugs fixed:

 * Fix exceeding IRQ routes that could have caused freezes of guests.
 (bnc#876842)
 * Fix CPUID emulation bugs that may have broken Windows guests with
 newer -cpu types (bnc#886535)

Security Issues:

 * CVE-2014-0222
 <[link moved to references]>
 * CVE-2014-0223
 <[link moved to references]>
 * CVE-2014-3461
 <[link moved to references]>");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~0.17.1", rls:"SLES11.0SP3"))) {
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
