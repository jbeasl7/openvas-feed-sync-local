# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122741");
  script_cve_id("CVE-2015-3276");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:18 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-28 18:28:00 +0000 (Fri, 28 Apr 2023)");

  script_name("Oracle: Security Advisory (ELSA-2015-2131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2131");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2131.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap' package(s) announced via the ELSA-2015-2131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.4.40-8]
- NSS does not support string ordering (#1231522)
- implement and correct order of parsing attributes (#1231522)
- add multi_mask and multi_strength to correctly handle sets of attributes (#1231522)
- add new cipher suites and correct AES-GCM attributes (#1245279)
- correct DEFAULT ciphers handling to exclude eNULL cipher suites (#1245279)

[2.4.40-7]
- Merge two MozNSS cipher suite definition patches into one. (#1245279)
- Use what NSS considers default for DEFAULT cipher string. (#1245279)
- Remove unnecessary defaults from ciphers' definitions (#1245279)

[2.4.40-6]
- fix: OpenLDAP shared library destructor triggers memory leaks in NSPR (#1249977)

[2.4.40-5]
- enhancement: support TLS 1.1 and later (#1231522,#1160467)
- fix: openldap ciphersuite parsing code handles masks incorrectly (#1231522)
- fix the patch in commit da1b5c (fix: OpenLDAP crash in NSS shutdown handling) (#1231228)

[2.4.40-4]
- fix: rpm -V complains (#1230263) -- make the previous fix do what was intended

[2.4.40-3]
- fix: rpm -V complains (#1230263)

[2.4.40-2]
- fix: missing frontend database indexing (#1226600)

[2.4.40-1]
- new upstream release (#1147982)
- fix: PIE and RELRO check (#1092562)
- fix: slaptest doesn't convert perlModuleConfig lines (#1184585)
- fix: OpenLDAP crash in NSS shutdown handling (#1158005)
- fix: slapd.service may fail to start if binding to NIC ip (#1198781)
- fix: deadlock during SSL_ForceHandshake when getting connection to replica (#1125152)
- improve check_password (#1174723, #1196243)
- provide an unversioned symlink to check_password.so.1.1 (#1174634)
- add findutils to requires (#1209229)");

  script_tag(name:"affected", value:"'openldap' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.40~8.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.40~8.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.40~8.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.40~8.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.4.40~8.el7", rls:"OracleLinux7"))) {
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
