# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122636");
  script_cve_id("CVE-2007-1716", "CVE-2007-3102");
  script_tag(name:"creation_date", value:"2015-10-08 11:49:56 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2007-0555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0555");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0555.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the ELSA-2007-0555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.99.6.2-3.26]
- removed realtime default limits (#240123) from the package as
 it caused regression on machines with nonexistent realtime group

[0.99.6.2-3.25]
- added and improved translations (#219124)
- adjusted the default limits for realtime users (#240123)

[0.99.6.2-3.23]
- pam_unix: truncated MD5 passwords in shadow shouldn't match (#219258)
- pam_limits: add limits.d support (#232700)
- pam_limits, pam_time, pam_access: add auditing of failed logins (#232993)
- pam_namespace: expand /home/ksharma even when appended with text (#237163)
 original patch by Ted X. Toth
- add some default limits for users in realtime group (#240123)
- CVE-2007-3102 - prevent audit log injection through user name (#243204)

[0.99.6.2-3.22]
- make unix_update helper executable only by root as it isn't
 useful for regular user anyway

[0.99.6.2-3.21]
- pam_namespace: better document behavior on failure (#237249)
- pam_unix: split out passwd change to a new helper binary (#236316)

[0.99.6.2-3.19]
- pam_selinux: improve context change auditing (#234781)

[0.99.6.2-3.18]
- pam_console: always decrement use count (#233581)
- pam_namespace: fix parsing config file with unknown users (#234513)

[0.99.6.2-3.17]
- pam_namespace: unmount poly dir for override users (#229689)
- pam_namespace: use raw context for poly dir name (#227345)
- pam_namespace: truncate long poly dir name (append hash) (#230120)

[0.99.6.2-3.15]
- correctly relabel tty in the default case (#229542)");

  script_tag(name:"affected", value:"'pam' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~0.99.6.2~3.26.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~0.99.6.2~3.26.el5", rls:"OracleLinux5"))) {
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
