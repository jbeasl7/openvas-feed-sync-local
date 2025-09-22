# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887365");
  script_tag(name:"creation_date", value:"2024-08-09 04:04:41 +0000 (Fri, 09 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-e142be4915)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e142be4915");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e142be4915");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp' package(s) announced via the FEDORA-2024-e142be4915 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Release notes for xrdp v0.10.1 (2024/07/31)

General announcements

A clipboard bugfix included in this release is sponsored by Kramer Pferdesport GmbH & Co KG. We very much appreciate the sponsorship.

Please consider sponsoring or making a donation to the project if you like xrdp. We accept financial contributions via Open Collective. Direct donations to each developer via GitHub Sponsors are also welcomed.
Security fixes

 - Unauthenticated RDP security scan finding / partial auth bypass (no CVE). Thanks to @txtdawg for reporting this.

New features

 - GFX-RFX lossy compression levels are now selectable depending on connection type on the client (#3183, backport of #2973)

Bug fixes

 - A regression in the code for creating the chansrv FUSE directory has been fixed (#3088, backport of #3082)
 - Fix a systemd dependency ('network-online.target') (#3088, backport of #3086)
 - A problem in session list processing which could result in incorrect display assignments has been fixed (#3088, backport of #3103)
 - A problem in GFX resizing which could lead to a SEGV in xrdp has been fixed (#3088, backport of #3107)
 - A problem with the US Dvorak keyboard layout has been resolved (#3088, backport of #3112)
 - A regression bug when pasting image to LibreOffice has been fixed [Sponsored by Kramer Pferdesport GmbH & Co KG] (#3102 #3120)
 - Fix a regression when the server tries to negotiate GFX when max_bpp is not high enough (#3118 #3122)
 - Fix a GFX multi-monitor screen placing issue on minimise/maximize (#3075 #3127)
 - Fix an issue some files are not included properly in release tarball (#3149 #3150)
 - Using 'I' in the session selection policy now works correctly (#3167 #3171)
 - A potential name buffer overflow in the redirector has been fixed [no security implications] (#3175)
 - Screens wider than 4096 pixels should now be supported (#3083)
 - An unnecessary licensing exchange during connection setup has been removed. This was causing problems for FIPS-compliant clients (#3132 backport of #3143)

Internal changes

 - FreeBSD CI bumped to 13.3 (#3088, backport of #3104)

Changes for users

 - None since v0.10.0.
 - If moving from v0.9.x, read the v0.10.0 release note.

Changes for packagers or developers

 - None since v0.10.0.
 - If moving from v0.9.x, read the v0.10.0 release note.");

  script_tag(name:"affected", value:"'xrdp' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.10.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debuginfo", rpm:"xrdp-debuginfo~0.10.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debugsource", rpm:"xrdp-debugsource~0.10.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.10.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-selinux", rpm:"xrdp-selinux~0.10.1~1.fc40", rls:"FC40"))) {
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
