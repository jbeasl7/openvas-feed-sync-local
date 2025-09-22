# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122784");
  script_cve_id("CVE-2015-2704");
  script_tag(name:"creation_date", value:"2015-11-25 11:18:51 +0000 (Wed, 25 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-2184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2184");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2184.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'realmd' package(s) announced via the ELSA-2015-2184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.16.1-5]
- Revert 0.16.1-4
- Use samba by default
- Resolves: rhbz#1271618

[0.16.1-4]
- Fix regressions in 0.16.x releases
- Resolves: rhbz#1258745
- Resolves: rhbz#1258488

[0.16.1-3]
- Fix regression accepting DNS domain names
- Resolves: rhbz#1243771

[0.16.1-2]
- Fix discarded patch: ipa-packages.patch

[0.16.1-1]
- Updated to upstream 0.16.1
- Resolves: rhbz#1241832
- Resolves: rhbz#1230941

[0.16.0-1]
- Updated to upstream 0.16.0
- Resolves: rhbz#1174911
- Resolves: rhbz#1142191
- Resolves: rhbz#1142148

[0.14.6-5]
- Don't crash when full_name_format is not in sssd.conf [#1051033]
 This is a regression from a prior update.

[0.14.6-4]
- Fix full_name_format printf(3) related failure [#1048087]

[0.14.6-3]
- Mass rebuild 2013-12-27

[0.14.6-2]
- Start oddjob after joining a domain [#967023]

[0.14.6-1]
- Update to upstream 0.14.6 point release
- Set 'kerberos method = system keytab' in smb.conf properly [#997580]
- Limit Netbios name to 15 chars when joining AD domain [#1001667]

[0.14.5-1]
- Update to upstream 0.14.5 point release
- Fix regression conflicting --unattended and -U as in --user args [#996223]
- Pass discovered server address to adcli tool [#996995]

[0.14.4-1]
- Update to upstream 0.14.4 point release
- Fix up the [sssd] section in sssd.conf if it's screwed up [#987491]
- Add an --unattended argument to realm command line client [#976593]
- Clearer 'realm permit' manual page example [#985800]

[0.14.3-1]
- Update to upstream 0.14.3 point release
- Populate LoginFormats correctly [#967011]
- Documentation clarifications [#985773] [#967565]
- Set sssd.conf default_shell per domain [#967569]
- Notify in terminal output when installing packages [#984960]
- If joined via adcli, delete computer with adcli too [#967008]
- If input is not a tty, then read from stdin without getpass()
- Configure pam_winbind.conf appropriately [#985819]
- Refer to FreeIPA as IPA [#967019]
- Support use of kerberos ccache to join when winbind [#985817]

[0.14.2-3]
- Run test suite when building the package
- Fix rpmlint errors

[0.14.2-2]
- Install oddjobd and oddjob-mkhomedir when joining domains [#969441]

[0.14.2-1]
- Update to upstream 0.14.2 version
- Discover FreeIPA 3.0 with AD trust correctly [#966148]
- Only allow joining one realm by default [#966650]
- Enable the oddjobd service after joining a domain [#964971]
- Remove sssd.conf allow lists when permitting all [#965760]
- Add dependency on authconfig [#964675]
- Remove glib-networking dependency now that we no longer use SSL.

[0.14.1-1]
- Update to upstream 0.14.1 version
- Fix crash/regression using passwords with joins [#961435]
- Make second Ctrl-C just quit realm tool [#961325]
- Fix critical warning when leaving IPA realm [#961320]
- Don't print out journalctl command in obvious situations [#961230]
- Document the --all option to 'realm discover' [#961279]
- No need to require sssd-tools package ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'realmd' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"realmd", rpm:"realmd~0.16.1~5.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realmd-devel-docs", rpm:"realmd-devel-docs~0.16.1~5.el7", rls:"OracleLinux7"))) {
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
