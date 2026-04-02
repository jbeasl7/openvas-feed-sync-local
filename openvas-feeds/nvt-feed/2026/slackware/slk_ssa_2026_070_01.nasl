# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.070.01");
  script_tag(name:"creation_date", value:"2026-03-13 04:35:08 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-13T15:49:08+0000");
  script_tag(name:"last_modification", value:"2026-03-13 15:49:08 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2026-070-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-070-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.401218");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SSA:2026-070-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libarchive packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/libarchive-3.8.6-i586-1_slack15.0.txz: Upgraded.
 This update fixes bugs and security issues:
 libarchive: fix incompatibility with Nettle 4.x (#2858)
 libarchive: fix NULL pointer dereference in
 archive_acl_from_text_w() (#2859)
 bsdunzip: fix ISO week year and Gregorian year confusion (#2860)
 7zip: ix SEGV in check_7zip_header_in_sfx via ELF offset validation (#2864)
 7zip: fix out-of-bounds access on ELF 64-bit header (#2875)
 RAR5 reader: fix infinite loop in rar5 decompression (#2877)
 RAR5 reader: fix potential memory leak (#2892)
 RAR5: fix SIGSEGV when archive_read_support_format_rar5 is called
 twice (#2893)
 CAB reader: fix memory leak on repeated calls to
 archive_read_support_format_cab (#2895)
 mtree reader: Fix file descriptor leak in mtree parser
 cleanup (CWE-775, #2878)
 various small bugfixes in code and documentation
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libarchive' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.8.6-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.8.6-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.8.6-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.8.6-x86_64-1", rls:"SLKcurrent"))) {
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
