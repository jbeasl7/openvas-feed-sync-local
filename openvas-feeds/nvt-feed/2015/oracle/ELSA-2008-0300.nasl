# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122582");
  script_cve_id("CVE-2007-6283", "CVE-2008-0122");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:36 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0300)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0300");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0300.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the ELSA-2008-0300 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[30:9.3.4-6.P1]
- final 5.2 version
- minor changes in initscript
 - improved patches for #250744 and #250901

[30:9.3.4-5.P1]
- improved patch to handle D-BUS races (#240876)
- updated named.root zone to affect root IPv6 migration

[30:9.3.4-4.P1]
- improved fix for #253537, posttrans script is now used
- do not call restorecon on chroot/proc

[30:9.3.4-3.P1]
- CVE-2008-0122 (small buffer overflow in inet_network)

[30:9.3.4-2.P1]
- ship /usr/include/dst/gssapi.h file

[30:9.3.4-1.P1]
- CVE-2007-6283 (#419421)

[30:9.3.4-0.9.2.P1]
- added GSS-TSIG support to nsupdate (#251528)

[30:9.3.4-0.9.1.P1]
- updated L.ROOT-SERVERS.NET address in lib/dns/rootns.c file

[30:9.3.4-0.9.P1]
- fixed building of SDB stuff (#240788)
- fixed race condition during DBUS initialization (#240876)
- initscript LSD standardization (#242734)
[command (#247148)]
- fixed wrong perms of named's ldap schema (#250118)
- suppressed errors from chroot's specfile scripts (#252334)
- fixed /dev/random SELinux labelling
- added configtest to usage report from named initscript (#250744)
- fixed rndc stop return value handler (#250901)
- fixed named.log sync in bind-chroot-admin (#247486)
- rebased to latest 9.3 maintenance release (9.3.4-P1, #353741)
- updated named.root file (new L.ROOT-SERVERS.NET, #363531)
- added GSS-TSIG support to named (#251528)
 - dropped patches (upstream)
 - bind-9.3.4.P1-query-id.patch
 - bind-9.3.3rc2-dbus-0.6.patch
 - bind-9.3.4-validator.patch
 - bind-9.3.4-nqueries.patch
 - updated patches
 - bind-9.3.2-tmpfile.patch");

  script_tag(name:"affected", value:"'bind' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.4~6.P1.el5", rls:"OracleLinux5"))) {
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
