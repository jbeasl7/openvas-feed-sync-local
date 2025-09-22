# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122744");
  script_cve_id("CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:20 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-2088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2088");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2088.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the ELSA-2015-2088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[6.6.1p1-22]
- Use the correct constant for glob limits (#1160377)

[6.6.1p1-21]
- Extend memory limit for remote glob in sftp acc. to stat limit (#1160377)

[6.6.1p1-20]
- Fix vulnerabilities published with openssh-7.0 (#1265807)
 - Privilege separation weakness related to PAM support
 - Use-after-free bug related to PAM support

[6.6.1p1-19]
- Increase limit of files for glob match in sftp to 8192 (#1160377)

[6.6.1p1-18]
- Add GSSAPIKexAlgorithms option for server and client application (#1253062)

[6.6.1p1-17]
- Security fixes released with openssh-6.9 (CVE-2015-5352) (#1247864)
 - XSECURITY restrictions bypass under certain conditions in ssh(1) (#1238231)
 - weakness of agent locking (ssh-add -x) to password guessing (#1238238)

[6.6.1p1-16]
- only query each keyboard-interactive device once (CVE-2015-5600) (#1245971)

[6.6.1p1-15]
- One more typo in manual page documenting TERM variable (#1162683)
- Fix race condition with auditing messages answers (#1240613)

[6.6.1p1-14]
- Fix ldif schema to have correct spacing on newlines (#1184938)
- Add missing values for sshd test mode (#1187597)
- ssh-copy-id: tcsh doesn't work with multiline strings (#1201758)
- Fix memory problems with newkeys and array transfers (#1223218)
- Enhance AllowGroups documentation in man page (#1150007)

[6.6.1p1-13]
- Increase limit of files for glob match in sftp (#1160377)
- Add pam_reauthorize.so to /etc/pam.d/sshd (#1204233)
- Show all config values in sshd test mode (#1187597)
- Document required selinux boolean for working ssh-ldap-helper (#1178116)
- Consistent usage of pam_namespace in sshd (#1125110)
- Fix auditing when using combination of ForcedCommand and PTY (#1199112)
- Add sftp option to force mode of created files (#1197989)
- Ability to specify an arbitrary LDAP filter in ldap.conf for ssh-ldap-helper (#1201753)
- Provide documentation line for systemd service and socket (#1181591)
- Provide LDIF version of LPK schema (#1184938)
- Document TERM environment variable (#1162683)
- Fix ssh-copy-id on non-sh remote shells (#1201758)
- Do not read RSA1 hostkeys for HostBased authentication in FIPS (#1197666)");

  script_tag(name:"affected", value:"'openssh' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server-sysvinit", rpm:"openssh-server-sysvinit~6.6.1p1~22.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~9.22.el7", rls:"OracleLinux7"))) {
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
