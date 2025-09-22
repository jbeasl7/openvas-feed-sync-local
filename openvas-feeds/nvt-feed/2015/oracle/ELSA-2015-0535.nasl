# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123171");
  script_cve_id("CVE-2014-7300");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-0535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0535");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0535.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clutter, cogl, gnome-shell, mutter' package(s) announced via the ELSA-2015-0535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"clutter
[1.14.4-12]
- Include upstream patch to prevent a crash when hitting hardware limits
 Resolves: rhbz#1115162

[1.14.4-11]
- Fix a typo in the Requires

[1.14.4-10]
- Add patch for quadbuffer stereo support
 Resolves: rhbz#1108891

cogl
[1.14.1-6]
- Add patches for quadbuffer stereo support
 Resolves: rhbz#1108890

[1.14.0-5.2]
- Ensure the glBlitFramebuffer case is not hit for swrast, since that's
 still broken.

gnome-shell
[3.8.4-45]
- Don't inform GDM about session changes that came from GDM
 Resolves: #1163474

[3.8.4-44]
- If password authentication is disabled and smartcard authentication is
 enabled and smartcard isn't plugged in at start up, prompt user for
 smartcard
 Resolves: #1159385

[3.8.4-43]
- Support long login banner messages more effectively
 Resolves: #1110036

[3.8.4-42]
- Respect disk-writes lockdown setting
 Resolves: rhbz#1154122

[3.8.4-41]
- Disallow consecutive screenshot requests to avoid an OOM situation
 Resolves: rhbz#1154107

[3.8.4-41]
- Add option to limit app switcher to current workspace
 Resolves: rhbz#1101568

[3.8.4-40]
- Try harder to use the default calendar application
 Resolves: rhbz#1052201

[3.8.4-40]
- Update workspace switcher fix
 Resolves: rhbz#1092102

[3.8.4-39]
- Validate screenshot parameters
 Resolves: rhbz#1104694

[3.8.4-38]
- Fix shrinking workspace switcher
 Resolves: rhbz#1092102

[3.8.4-38]
- Update fix for vertical monitor layouts to upstream fix
 Resolves: rhbz#1075240

[3.8.4-38]
- Fix traceback introduced in 3.8.4-36 when unlocking via
 user switcher
 Related: #1101333

[3.8.4-37]
- Fix problems with LDAP and disable-user-list=TRUE
 Resolves: rhbz#1137041

[3.8.4-36]
- Fix login screen focus issue following idle
 Resolves: rhbz#1101333

[3.8.4-35]
- Disallow cancel from login screen before login attempt
 has been initiated.
 Resolves: rhbz#1109530

[3.8.4-34]
- Disallow cancel from login screen after login is already
 commencing.
 Resolves: rhbz#1079294

[3.8.4-33]
- Add a patch for quadbuffer stereo support
 Resolves: rhbz#1108893

mutter
[3.8.4.16]
- Fix window placement regression
 Resolves: rhbz#1153641

[3.8.4-15]
- Fix delayed mouse mode
 Resolves: rhbz#1149585

[3.8.4-14]
- Preserve window placement on monitor changes
 Resolves: rhbz#1126754

[3.8.4-13]
- Improve handling of vertical monitor layouts
 Resolves: rhbz#1108322

[3.8.4-13]
- Add patches for quadbuffer stereo support
 Fix a bad performance problem drawing window thumbnails
 Resolves: rhbz#861507");

  script_tag(name:"affected", value:"'clutter, cogl, gnome-shell, mutter' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"clutter", rpm:"clutter~1.14.4~12.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clutter-devel", rpm:"clutter-devel~1.14.4~12.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clutter-doc", rpm:"clutter-doc~1.14.4~12.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cogl", rpm:"cogl~1.14.0~6.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cogl-devel", rpm:"cogl-devel~1.14.0~6.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cogl-doc", rpm:"cogl-doc~1.14.0~6.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.8.4~45.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-browser-plugin", rpm:"gnome-shell-browser-plugin~3.8.4~45.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutter", rpm:"mutter~3.8.4~16.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutter-devel", rpm:"mutter-devel~3.8.4~16.el7", rls:"OracleLinux7"))) {
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
