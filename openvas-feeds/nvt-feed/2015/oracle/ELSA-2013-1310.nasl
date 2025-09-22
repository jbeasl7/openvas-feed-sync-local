# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123558");
  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:30 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1310");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1310.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba3x' package(s) announced via the ELSA-2013-1310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.6.6-0.136]
- resolves: #984807 - CVE-2013-4124: DoS via integer overflow when reading
 an EA list

[3.6.6-0.135]
- Fix PIDL parsing with newer versions of gcc.
- Fix dereferencing a unique pointer in the WKSSVC server.
- resolves: #982484

[3.6.6-0.134]
- Check for system libtevent and require version 0.9.18.
- Use tevent epoll backend in winbind.
- resolves: #869295

[3.6.6-0.133]
- Fix smbstatus code dump when a file entry has delete tokens.
- resolves: #962840

[3.6.6-0.132]
- Fix possible segfaults with group caching patch.
- related: #948923

[3.6.6-0.131]
- Fix CVE-2013-0213 and CVE-2013-0214.
- resolves: #957591

[3.6.6-0.130]
- Fix netlogon failover for LogonSamLogon.
- resolves: #862872
- Fix write operations as guest with security = share
- resolves: #905071
- Disable building cifs idmap and acl binaries.
- resolves: #873692
- Change chkconfig order to start winbind before netfs.
- resolves: #948614
- Fix cache issue when resoliving groups without domain name.
- resolves: #948923
- Fix pam_winbind upn to username conversion if you have different separator.
- resolves: #949611
- Fix the username map optimization.
- resolves: #917564
- Fix leaking sockets of smb dc connection.
- resolves: #883861
- Fix 'net ads keytab add' not respecting the case.
- resolves: #955680
- Fix 'map untrusted to domain' with NTLMv2.
- resolves: #947999");

  script_tag(name:"affected", value:"'samba3x' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.6.6~0.136.el5", rls:"OracleLinux5"))) {
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
