# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3685.1");
  script_cve_id("CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15858", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:34 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 17:12:08 +0000 (Thu, 01 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3685-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183685-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxkbcommon' package(s) announced via the SUSE-SU-2018:3685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxkbcommon to version 0.8.2 fixes the following issues:
Fix a few NULL-dereferences, out-of-bounds access and undefined behavior
 in the XKB text format parser.

CVE-2018-15853: Endless recursion could have been used by local
 attackers to crash xkbcommon users by supplying a crafted keymap file
 that triggers boolean negation (bsc#1105832).

CVE-2018-15854: Unchecked NULL pointer usage could have been used by
 local attackers to crash (NULL pointer dereference) the xkbcommon parser
 by supplying a crafted keymap file, because geometry tokens were
 desupported incorrectly (bsc#1105832).

CVE-2018-15855: Unchecked NULL pointer usage could have been used by
 local attackers to crash (NULL pointer dereference) the xkbcommon parser
 by supplying a crafted keymap file, because the XkbFile for an
 xkb_geometry section was mishandled (bsc#1105832).

CVE-2018-15856: An infinite loop when reaching EOL unexpectedly could be
 used by local attackers to cause a denial of service during parsing of
 crafted keymap files (bsc#1105832).

CVE-2018-15857: An invalid free in ExprAppendMultiKeysymList could have
 been used by local attackers to crash xkbcommon keymap parsers or
 possibly have unspecified other impact by supplying a crafted keymap
 file (bsc#1105832).

CVE-2018-15858: Unchecked NULL pointer usage when handling invalid
 aliases in CopyKeyAliasesToKeymap could have been used by local
 attackers to crash (NULL pointer dereference) the xkbcommon parser by
 supplying a crafted keymap file (bsc#1105832).

CVE-2018-15859: Unchecked NULL pointer usage when parsing invalid atoms
 in ExprResolveLhs could have been used by local attackers to crash (NULL
 pointer dereference) the xkbcommon parser by supplying a crafted keymap
 file, because lookup failures are mishandled (bsc#1105832).

CVE-2018-15861: Unchecked NULL pointer usage in ExprResolveLhs could
 have been used by local attackers to crash (NULL pointer dereference)
 the xkbcommon parser by supplying a crafted keymap file that triggers an
 xkb_intern_atom failure (bsc#1105832).

CVE-2018-15862: Unchecked NULL pointer usage in LookupModMask could have
 been used by local attackers to crash (NULL pointer dereference) the
 xkbcommon parser by supplying a crafted keymap file with invalid virtual
 modifiers (bsc#1105832).

CVE-2018-15863: Unchecked NULL pointer usage in ResolveStateAndPredicate
 could have been used by local attackers to crash (NULL pointer
 dereference) the xkbcommon parser by supplying a crafted keymap file
 with a no-op modmask expression (bsc#1105832).

CVE-2018-15864: Unchecked NULL pointer usage in resolve_keysym could
 have been used by local attackers to crash (NULL pointer dereference)
 the xkbcommon parser by supplying a crafted keymap file, because a map
 access attempt can
 occur for a map that was never created (bsc#1105832).");

  script_tag(name:"affected", value:"'libxkbcommon' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-debugsource", rpm:"libxkbcommon-debugsource~0.8.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-devel", rpm:"libxkbcommon-devel~0.8.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-0", rpm:"libxkbcommon-x11-0~0.8.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-0-debuginfo", rpm:"libxkbcommon-x11-0-debuginfo~0.8.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon-x11-devel", rpm:"libxkbcommon-x11-devel~0.8.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon0", rpm:"libxkbcommon0~0.8.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxkbcommon0-debuginfo", rpm:"libxkbcommon0-debuginfo~0.8.2~3.3.1", rls:"SLES15.0"))) {
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
