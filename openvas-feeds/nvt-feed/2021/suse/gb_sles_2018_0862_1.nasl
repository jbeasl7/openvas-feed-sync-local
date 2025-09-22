# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0862.1");
  script_cve_id("CVE-2012-6706", "CVE-2017-12938", "CVE-2017-12940", "CVE-2017-12941", "CVE-2017-12942");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-21 17:06:16 +0000 (Mon, 21 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0862-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0862-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180862-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/513804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693890");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003863.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrar' package(s) announced via the SUSE-SU-2018:0862-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unrar to version 5.6.1 fixes several issues.

These security issues were fixed:

- CVE-2017-12938: Prevent remote attackers to bypass a directory-traversal
 protection mechanism via vectors involving a symlink to the . directory, a
 symlink to the .. directory, and a regular file (bsc#1054038).
- CVE-2017-12940: Prevent out-of-bounds read in the EncodeFileName::Decode call
 within the Archive::ReadHeader15 function (bsc#1054038).
- CVE-2017-12941: Prevent an out-of-bounds read in the Unpack::Unpack20
 function (bsc#1054038).
- CVE-2017-12942: Prevent a buffer overflow in the Unpack::LongLZ function
 (bsc#1054038).

These non-security issues were fixed:

- Added extraction support for .LZ archives created by Lzip compressor
- Enable unpacking of files in ZIP archives compressed with XZ algorithm and
 encrypted with AES
- Added support for PAX extended headers inside of TAR archive
- If RAR recovery volumes (.rev files) are present in the same folder as usual
 RAR volumes, archive test command verifies .rev contents after completing
 testing .rar files
- By default unrar skips symbolic links with absolute paths in link target when
 extracting unless -ola command line switch is specified
- Added support for AES-NI CPU instructions
- Support for a new RAR 5.0 archiving format
- Wildcard exclusion mask for folders
- Added libunrar* and libunrar*-devel subpackages (bsc#513804)
- Prevent conditional jumps depending on uninitialised values (bsc#1046882)");

  script_tag(name:"affected", value:"'unrar' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.6.1~5.3.1", rls:"SLES11.0SP4"))) {
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
