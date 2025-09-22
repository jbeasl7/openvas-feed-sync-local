# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0298.1");
  script_cve_id("CVE-2013-2020", "CVE-2013-2021", "CVE-2013-6497", "CVE-2014-9050", "CVE-2014-9328", "CVE-2015-1461", "CVE-2015-1462", "CVE-2015-1463", "CVE-2015-2170", "CVE-2015-2221", "CVE-2015-2222", "CVE-2015-2305", "CVE-2015-2668");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP1|SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0298-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150298-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929192");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001230.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2015:0298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The antivirus scanner ClamAV has been updated to version 0.98.3, which
includes the following fixes and enhancements:

 * Support for common raw disk image formats using 512 byte sectors,
 specifically GPT, APM, and MBR partitioning.
 * All ClamAV sockets (clamd, freshclam, clamav-milter, clamdscan,
 clamdtop) now support IPV6 addresses and configuration parameters.
 * Use OpenSSL file hash functions for improved performance.
 * Improved detection of malware scripts within image files.
 * Miscellaneous bug fixes and documentation improvements.");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP2, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~0.8.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.3~0.11.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.97.8~0.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.3~0.11.1", rls:"SLES11.0SP3"))) {
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
