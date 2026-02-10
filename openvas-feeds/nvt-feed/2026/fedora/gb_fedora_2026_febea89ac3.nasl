# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10210198101978997993");
  script_cve_id("CVE-2025-68670");
  script_tag(name:"creation_date", value:"2026-02-09 04:51:40 +0000 (Mon, 09 Feb 2026)");
  script_version("2026-02-09T06:03:20+0000");
  script_tag(name:"last_modification", value:"2026-02-09 06:03:20 +0000 (Mon, 09 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-06 19:59:50 +0000 (Fri, 06 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-febea89ac3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-febea89ac3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-febea89ac3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1908387");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279775");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322105");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2323097");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433438");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433439");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433440");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433441");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433442");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433840");
  script_xref(name:"URL", value:"https://github.com/neutrinolabs/xrdp/wiki/Running-the-xrdp-process-as-non-root");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorgxrdp, xrdp' package(s) announced via the FEDORA-2026-febea89ac3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Release notes for xrdp v0.10.5 (2026/01/27)

Security fixes

- CVE-2025-68670: Improper bounds checking of domain string length leads to Stack-based Buffer Overflow

New features

- It is now possible to start the xrdp daemon entirely unprivileged from the service manager (#3599 #3603). If you do this certain restrictions will apply. See [link moved to references] for details.
- TLS pre-master secrets can now be recorded for packet captures (#3617)
- Add a FuseRootReportMaxFree to work around 'no free space' issues with some file managers (#3639)
- Alternate shell names can now be passed to startwm.sh in an environment variable for more system management control (#3624 #3651)
- Updated Xorg paths in sesman.ini to include more recent distros (#3663)
- Add Slovenian keyboard (#3668 #3670)
- xrdpapi: Add a way to monitor connect/disconnect events (#3693)

Bug fixes

- Allow an empty X11 UTF8_STRING to be pasted to the clipboard (#3580 #3582)
- Fix a regression introduced in v0.10.x, where it became impossible to connect to a VNC server which did not support the ExtendedDesktopSize encoding (#3540 #3584)
- Fix a regression introduced in v0.10.x related to PAM groups handling (#3594)
- Inconsistencies with [MS-RDPBCGR] have been addressed (#3608)
- A reference to uninitialised data within the verify_user_pam_userpass.c module has been fixed (#3638)
- Prevent some possible crashes when the RFX encoder is resized (#3590 #3644)
- Fixes a regression introduced by GFX development which prevented the JPEG encoder from working correctly (#3649)
- Fixes a regression introduced by #2974 which resulted in the xrdp PID file being deleted unexpectedly (#3650)
- Do not overwrite a VNC port set by the user when not using sesman (#3674)
- Fix regression from 0.9.x when freerdp client uses /workarea (#3618 #3676)
- Fixes a crash where a resize is attempted with drdynvc disabled (#3672 #3680)
- getgrouplist() now compiles on MacOS (#3575)
- Various Coverity warnings have been addressed (#3656)
- Documentation improvements (#3665)

Internal changes

- An unnecessary include of sys/signal.h causing a compile warning on MUSL-C has been removed (#3679)

Release notes for xorgxrdp v0.10.5 (2026/01/28)

Bug fixes

- Fix bug in Chrome pointer detection (#394 #396)

Internal changes

- CI: Update FreeBSD xrdp dependency (#398)");

  script_tag(name:"affected", value:"'xorgxrdp, xrdp' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"xorgxrdp", rpm:"xorgxrdp~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorgxrdp-debuginfo", rpm:"xorgxrdp-debuginfo~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorgxrdp-debugsource", rpm:"xorgxrdp-debugsource~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorgxrdp-glamor", rpm:"xorgxrdp-glamor~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorgxrdp-glamor-debuginfo", rpm:"xorgxrdp-glamor-debuginfo~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debuginfo", rpm:"xrdp-debuginfo~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debugsource", rpm:"xrdp-debugsource~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-selinux", rpm:"xrdp-selinux~0.10.5~1.fc43", rls:"FC43"))) {
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
