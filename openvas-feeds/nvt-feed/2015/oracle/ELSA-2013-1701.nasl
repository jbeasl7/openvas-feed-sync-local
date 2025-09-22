# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123520");
  script_cve_id("CVE-2013-1775", "CVE-2013-2776", "CVE-2013-2777");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1701)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1701");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1701.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the ELSA-2013-1701 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.8.6p3-12]
- added patches for CVE-2013-1775 CVE-2013-2777 CVE-2013-2776
 Resolves: rhbz#1015355

[1.8.6p3-11]
- sssd: fixed a bug in ipa_hostname processing
 Resolves: rhbz#853542

[1.8.6p3-10]
- sssd: fixed buffer size for the ipa_hostname value
 Resolves: rhbz#853542

[1.8.6p3-9]
- sssd: match against ipa_hostname from sssd.conf too when
 checking sudoHost
 Resolves: rhbz#853542

[1.8.6p3-8]
- updated man-page
- fixed handling of RLIMIT_NPROC resource limit
- fixed alias cycle detection code
- added debug messages for tracing of netgroup matching
- fixed aborting on realloc when displaying allowed commands
- show the SUDO_USER in logs, if running commands as root
- sssd: filter netgroups in the sudoUser attribute
 Resolves: rhbz#856901
 Resolves: rhbz#947276
 Resolves: rhbz#886648
 Resolves: rhbz#994563
 Resolves: rhbz#848111
 Resolves: rhbz#994626
 Resolves: rhbz#973228
 Resolves: rhbz#880150");

  script_tag(name:"affected", value:"'sudo' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.6p3~12.el6", rls:"OracleLinux6"))) {
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
