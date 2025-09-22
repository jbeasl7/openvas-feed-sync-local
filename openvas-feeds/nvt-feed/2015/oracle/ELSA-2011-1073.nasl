# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122123");
  script_cve_id("CVE-2008-5374");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:27 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-1073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1073");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash' package(s) announced via the ELSA-2011-1073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.2-32]
- Don't include backup files
 Resolves: #700157

[3.2-31]
- Use 'mktemp' for temporary files
 Resolves: #700157

[3.2-30]
- Added man page references to systemwide .bash_logout
 Resolves: #592979

[3.2-29]
- Readline glitch, when editing line with more spaces and resizing window
 Resolves: #525474

[3.2-28]
- Fix the memory leak in read builtin
 Resolves: #618393
- Don't append slash to non-directories
 Resolves: #583919

[3.2-27]
- Test .dynamic section if has PROGBITS or NOBITS
 Resolves: #484809
- Better random number generator
 Resolves: #492908
- Allow to source scripts with embedded NULL chars
 Resolves: #503701

[3.2-26]
- vi mode redo insert fixed
 Resolves: #575076
- Don't show broken pipe messages for builtins
 Resolves: #546529
- Don't include loadables in doc dir
 Resolves: #663656
- Enable system-wide .bash_logout for login shells
 Resolves: #592979

[3.2-25]
- Don't abort source builtin
 Resolves: #448508
- Correctly place cursor
 Resolves: #463880
- Minor man page clarification for trap builtin
 Resolves: #504904");

  script_tag(name:"affected", value:"'bash' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"bash", rpm:"bash~3.2~32.el5", rls:"OracleLinux5"))) {
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
