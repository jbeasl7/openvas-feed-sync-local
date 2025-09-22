# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0290.1");
  script_cve_id("CVE-2014-5351", "CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0290-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0290-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150290-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912002");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001224.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the SUSE-SU-2015:0290-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MIT kerberos krb5 was updated to fix several security issues and bugs.

Security issues fixed:
CVE-2014-5351: The kadm5_randkey_principal_3 function in lib/kadm5/srv/svr_principal.c in kadmind in MIT Kerberos 5 (aka krb5)
sent old keys in a response to a -randkey -keepold request, which allowed remote authenticated users to forge tickets by leveraging administrative access.

CVE-2014-5352: In the MIT krb5 libgssapi_krb5 library, after gss_process_context_token() is used to process a valid context deletion token, the caller was left with a security context handle containing a dangling pointer. Further uses of this handle would have resulted in use-after-free and double-free memory access violations.
libgssrpc server applications such as kadmind were vulnerable as they can be instructed to call gss_process_context_token().

CVE-2014-9421: If the MIT krb5 kadmind daemon receives invalid XDR data from an authenticated user, it may have performed use-after-free and double-free memory access violations while cleaning up the partial deserialization results. Other libgssrpc server applications might also been vulnerable if they contain insufficiently defensive XDR functions.

CVE-2014-9422: The MIT krb5 kadmind daemon incorrectly accepted authentications to two-component server principals whose first component is a left substring of 'kadmin' or whose realm is a left prefix of the default realm.

CVE-2014-9423: libgssrpc applications including kadmind output four or eight bytes of uninitialized memory to the network as part of an unused 'handle' field in replies to clients.

Bugs fixed:
- Work around replay cache creation race, (bnc#898439).");

  script_tag(name:"affected", value:"'krb5' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-doc", rpm:"krb5-doc~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.12.1~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.1~9.1", rls:"SLES12.0"))) {
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
