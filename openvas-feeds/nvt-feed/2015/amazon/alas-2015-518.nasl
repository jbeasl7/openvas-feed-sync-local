# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120539");
  script_cve_id("CVE-2014-5352", "CVE-2014-5353", "CVE-2014-5355", "CVE-2014-9421", "CVE-2014-9422");
  script_tag(name:"creation_date", value:"2015-09-08 11:29:00 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-518");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-518.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ALAS-2015-518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in the way the MIT Kerberos libgssapi_krb5 library processed valid context deletion tokens. An attacker able to make an application using the GSS-API library (libgssapi) could call the gss_process_context_token() function and use this flaw to crash that application. (CVE-2014-5352)

If kadmind were used with an LDAP back end for the KDC database, a remote, authenticated attacker who has the permissions to set the password policy could crash kadmind by attempting to use a named ticket policy object as a password policy for a principal. (CVE-2014-5353)

It was found that the krb5_read_message() function of MIT Kerberos did not correctly sanitize input, and could create invalid krb5_data objects. A remote, unauthenticated attacker could use this flaw to crash a Kerberos child process via a specially crafted request. (CVE-2014-5355)

A double-free flaw was found in the way MIT Kerberos handled invalid External Data Representation (XDR) data. An authenticated user could use this flaw to crash the MIT Kerberos administration server (kadmind), or other applications using Kerberos libraries, via specially crafted XDR packets. (CVE-2014-9421)

It was found that the MIT Kerberos administration server (kadmind) incorrectly accepted certain authentication requests for two-component server principal names. A remote attacker able to acquire a key with a particularly named principal (such as 'kad/x') could use this flaw to impersonate any user to kadmind, and perform administrative actions as that user. (CVE-2014-9422)");

  script_tag(name:"affected", value:"'krb5' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.10.3~37.29.amzn1", rls:"AMAZON"))) {
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
