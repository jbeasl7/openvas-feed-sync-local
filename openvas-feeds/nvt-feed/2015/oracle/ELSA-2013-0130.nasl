# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123758");
  script_cve_id("CVE-2008-0455", "CVE-2008-0456", "CVE-2012-2687");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-0130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0130");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0130.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the ELSA-2013-0130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2.3-74.0.1.el5]
- fix mod_ssl always performing full renegotiation (Joe Jin) [orabug 12423387]
- replace index.html with Oracle's index page oracle_index.html
- update vstring and distro in specfile

[2.2.3-74]
- further %post scriptlet fix (#752618, #867736)

[2.2.3-73]
- fix %post scriptlet output (#752618, #867736)

[2.2.3-72]
- add security fix for CVE-2008-0456

[2.2.3-71]
- add security fix for CVE-2012-2687 (#850794)

[2.2.3-70]
- relax checks for status-line validity (#853128)

[2.2.3-69]
- mod_cache: fix header merging for 304 case, thanks to Roy Badami (#845532)
- correct CVE reference in old changelog entry (#849160)

[2.2.3-68]
- mod_ssl: add _userID DN variable suffix for NID_userId (#840036)
- fix handling of long chunk-line (#840845)
- omit %posttrans daemon restart if
 /etc/sysconfig/httpd-disable-posttrans exists (#833042)

[2.2.3-67]
- add server aliases to 'httpd -S' output (#833043)
- LSB compliance fixes for init script (#783242)
- mod_ldap: add LDAPReferrals directive alias (#727342)

[2.2.3-66]
- check if localhost.key is valid (#752618)
- mod_proxy_ajp: honour ProxyErrorOverride (#767890)
- mod_ssl: fixed start with FIPS 140-2 mode enabled (#773473)");

  script_tag(name:"affected", value:"'httpd' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~74.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~74.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~74.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~74.0.1.el5", rls:"OracleLinux5"))) {
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
