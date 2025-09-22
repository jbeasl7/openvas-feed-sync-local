# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3048.1");
  script_cve_id("CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9621", "CVE-2014-9653");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3048-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173048-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996511");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003403.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'file' package(s) announced via the SUSE-SU-2017:3048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The GNU file utility was updated to version 5.22.

Security issues fixed:

- CVE-2014-9621: The ELF parser in file allowed remote attackers to cause a denial of service via a long string. (bsc#913650)
- CVE-2014-9620: The ELF parser in file allowed remote attackers to cause a denial of service via a large number of notes. (bsc#913651)
- CVE-2014-9653: readelf.c in file did not consider that pread calls sometimes read only a subset of the available data, which allows remote attackers to cause a denial of service (uninitialized memory access) or possibly have unspecified other impact via a crafted ELF file. (bsc#917152)
- CVE-2014-8116: The ELF parser (readelf.c) in file allowed remote attackers to cause a denial of service (CPU consumption or crash) via a large number of (1) program or (2) section headers or (3) invalid capabilities. (bsc#910253)
- CVE-2014-8117: softmagic.c in file did not properly limit recursion, which allowed remote attackers to cause a denial of service (CPU consumption or crash) via unspecified vectors. (bsc#910253)

Version update to file version 5.22

* add indirect relative for TIFF/Exif
* restructure elf note printing to avoid repeated messages
* add note limit, suggested by Alexander Cherepanov
* Bail out on partial pread()'s (Alexander Cherepanov)
* Fix incorrect bounds check in file_printable (Alexander Cherepanov)
* PR/405: ignore SIGPIPE from uncompress programs
* change printable -> file_printable and use it in more places for safety
* in ELF, instead of '(uses dynamic libraries)' when PT_INTERP is present print the interpreter name.

Version update to file version 5.21

* there was an incorrect free in magic_load_buffers()
* there was an out of bounds read for some pascal strings
* there was a memory leak in magic lists
* don't interpret strings printed from files using the current
 locale, convert them to ascii format first.
* there was an out of bounds read in elf note reads

Update to file version 5.20

* recognize encrypted CDF documents
* add magic_load_buffers from Brooks Davis
* add thumbs.db support

Additional non-security bug fixes:

* Fixed a memory corruption during rpmbuild (bsc#1063269)
* Backport of a fix for an increased printable string length as found in file 5.30 (bsc#996511)
* file command throws 'Composite Document File V2 Document, corrupt: Can't read SSAT' error against excel 97/2003 file format. (bsc#1009966)");

  script_tag(name:"affected", value:"'file' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.22~10.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-magic", rpm:"file-magic~5.22~10.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic1-32bit", rpm:"libmagic1-32bit~5.22~10.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic1", rpm:"libmagic1~5.22~10.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.22~10.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-magic", rpm:"file-magic~5.22~10.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic1-32bit", rpm:"libmagic1-32bit~5.22~10.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic1", rpm:"libmagic1~5.22~10.3.1", rls:"SLES12.0SP3"))) {
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
