# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122030");
  script_cve_id("CVE-2011-3636");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:56 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1533");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1533.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa' package(s) announced via the ELSA-2011-1533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.1.3-9.el6]
- Add current password prompt when changing own password in web UI (#751179)
- Remove extraneous trailing ' from netgroup patch (#749352)

[2.1.3-8.el6]
- Updated patch for CVE-2011-3636 to include CR in the HTTP headers.
 xmlrpc-c in RHEL-6 doesn't suppose the dont_advertise option so that is
 not set any more. Another fake header, X-Original-User_Agent, is added
 so there is no more trailing junk after the Referer header. (#749870)

[2.1.3-7.el6]
- Require an HTTP Referer header to address CSRF attackes. CVE-2011-3636.
 (#749870)

[2.1.3-6.el6]
- Users not showing up in nis netgroup triple (#749352)

[2.1.3-5.el6]
- Add update file to remove entitlement roles, privileges and
 permissions (#739060)

[2.1.3-4.el6]
- Quote worker option in krb5kdc (#748754)

[2.1.3-3.el6]
- hbactest fails while you have svcgroup in hbacrule (#746227)
- Add Kerberos domain mapping for system hostname (#747443)
- Format certificates as PEM in browser (#701325)

[2.1.3-2.el6]
- ipa-client-install hangs if the discovered server is unresponsive (#745392)
- Fix minor problems in help system (#747028)
- Remove help fix from Disable automember patch (#746717)
- Update minimum version of sssd to 1.5.1-60 to pick up SELinux fix (#746265)

[2.1.3-1.el6]
- Update to upstream 2.1.3 release (#736170)
- Additional branding (#742264)
- Disable automember cli (#746717)
- ipa-client-install sometimes fails to start sssd properly (#736954)
- ipa-client-install adds duplicate information to krb5.conf (#714597)
- ipa-client-install should configure hostname (#714919)
- inconsistency in enabling 'delete' buttons (#730751)
- hbactest does not resolve canonical names during simulation (#740850)
- Default DNS Administration Role - Permissions missing (#742327)
- named fails to start after installing ipa server when short (#742875)
- Duplicate hostgroup and netgroup should not be allowed (#743253)
- named fails to start (#743680)
- Global password policy should not be able to be deleted (#744074)
- Client install fails when anonymous bind is disabled (#744101)
- Internal Server Error adding invalid reverse DNS zone (#744234)
- ipa hbactest does not evaluate indirect members from groups. (#744410)
- Leaks KDC password and master password via command line arguments (#744422)
- Traceback when upgrading from ipa-server-2.1.1-1 (#744798)
- IPA User's Primary GID is not being set to their UPG's GID (#745552)
- --forwarder option of ipa-dns-install allows invalid IP addr (#745698)
- UI does not grant access based on roles (#745957)
- Unable to add external user for RunAs User for Sudo (#746056)
- Typo in error message while adding invalid ptr record. (#746199)
- Don't use python 2.7-only syntax (#746229)
- Error when using ipa-client-install with --no-sssd option (#746276)
- Installation fails if sssd.conf exists and is already config (#746298)
- External hosts are not removed properly from sudorule ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ipa' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipa", rpm:"ipa~2.1.3~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~2.1.3~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~2.1.3~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~2.1.3~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~2.1.3~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~2.1.3~9.el6", rls:"OracleLinux6"))) {
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
