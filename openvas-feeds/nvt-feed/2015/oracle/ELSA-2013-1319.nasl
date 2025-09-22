# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123559");
  script_cve_id("CVE-2013-0219");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:31 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1319");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1319.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the ELSA-2013-1319 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.1-70]
- Fix IPA provider performance issue when storing large host groups
- Resolves: rhbz#979047 - sssd_be goes to 99% CPU and causes significant
 login delays when client is under load

[1.5.1-69]
- Fix startup with a broken configuration
- Resolves: rhbz#974036 - sssd core process keeps running after backends quit

[1.5.1-68]
- Add a forgotten break in a switch statement
- Related: rhbz#886165 - sssd will stop functioning correctly if sssd_be
 hangs for a while

[1.5.1-67]
- Fix initialization of the paging control
- Related: rhbz#886165 - sssd segfaults (sssd_be & sssd_pam) and corrupts
 cache repeatedly

[1.5.1-66]
- Resolves: rhbz#961680 - sssd components seem to mishandle sighup

[1.5.1-65]
- Resolves: rhbz#959838 - CVE-2013-0219 sssd: TOCTOU race conditions by
 copying and removing directory trees

[1.5.1-64]
- Free the LDAP control when following referrals
- Resolves: rhbz#820908 - SSSD stops working due to memory problems

[1.5.1-63]
- Restart services with a timeout in case they are restarted too often
- Resolves: rhbz#950156 - sssd dead but pid file exists after heavy load
 presented

[1.5.1-62]
- Use the LDAP paging control more sparingly
- Related: rhbz#886165 - sssd segfaults (sssd_be & sssd_pam) and corrupts
 cache repeatedly

[1.5.1-61]
- Resolves: rhbz#886165 - sssd segfaults (sssd_be & sssd_pam) and corrupts
 cache repeatedly

[1.5.1-60]
- Resolves: rhbz#886165 - sssd will stop functioning correctly if sssd_be
 hangs for a while

[1.5.1-59]
- Process pending requests on PAM reconnect
- Resolves: rhbz#882414 - sssd will stop perform LDAP requests for user
 lookup (nss), authorization, and authentication

[1.5.1-58]
- Initialize hbac_ctx to NULL
- Resolves: rhbz#850722

[1.5.1-57]
- Process all groups from a single nesting level
- Resolves: rhbz#846664
- Backport the option to disable srchost processing
- Resolves: rhbz#841677

[1.5.1-56]
- Require libgssapiv2.so to pull in cyrus-sasl-gssapi
- Resolves: rhbz#786443

[1.5.1-55]
- Rebuild against newer libtdb
- Related: rhbz#838130 - SSSD needs to be rebuilt against newer libtdb

[1.5.1-54]
- Resolves: rhbz#797272 - sssd-1.5.1-37.el5 needs a dependency to dbus >= 1.1
- Resolves: rhbz#797300 - Logging in with ssh pub key should consult
 authentication authority policies
- Resolves: rhbz#833169 - Add support for terminating idle connections in
 sssd_nss
- Resolves: rhbz#783081 - sssd_be crashes during auth when there exists UTF
 source host group in an hbacrule
- Resolves: rhbz#786443 - sssd on ppc64 doesn't pull cyrus-sasl-gssapi.ppc as
 a dependency
- Resolves: rhbz#827469 - Unable to lookup user, group, netgroup aliases with
 case_sensitive=false

[1.5.1-53]
- Resolves: rhbz#826237 - sssd_be segfaulting with IPA backend

[1.5.1-52]
- Resolves: rhbz#817073 - sssd fails to use the last AD server if other AD
 servers are not reachable
- Resolves: rhbz#828190 - Infinite loop checking Kerberos ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'sssd' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.5.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.5.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.5.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.5.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.5.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.5.1~70.el5", rls:"OracleLinux5"))) {
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
