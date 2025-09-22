# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703000");
  script_cve_id("CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345");
  script_tag(name:"creation_date", value:"2014-08-08 22:00:00 +0000 (Fri, 08 Aug 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3000-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3000-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3000");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-3000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in krb5, the MIT implementation of Kerberos. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-4341

An unauthenticated remote attacker with the ability to inject packets into a legitimately established GSSAPI application session can cause a program crash due to invalid memory references when attempting to read beyond the end of a buffer.

CVE-2014-4342

An unauthenticated remote attacker with the ability to inject packets into a legitimately established GSSAPI application session can cause a program crash due to invalid memory references when reading beyond the end of a buffer or by causing a null pointer dereference.

CVE-2014-4343

An unauthenticated remote attacker with the ability to spoof packets appearing to be from a GSSAPI acceptor can cause a double-free condition in GSSAPI initiators (clients) which are using the SPNEGO mechanism, by returning a different underlying mechanism than was proposed by the initiator. A remote attacker could exploit this flaw to cause an application crash or potentially execute arbitrary code.

CVE-2014-4344

An unauthenticated or partially authenticated remote attacker can cause a NULL dereference and application crash during a SPNEGO negotiation by sending an empty token as the second or later context token from initiator to acceptor.

CVE-2014-4345

When kadmind is configured to use LDAP for the KDC database, an authenticated remote attacker can cause it to perform an out-of-bounds write (buffer overflow).

For the stable distribution (wheezy), these problems have been fixed in version 1.10.1+dfsg-5+deb7u2.

For the unstable distribution (sid), these problems have been fixed in version 1.12.1+dfsg-7.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-doc", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-locales", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-user", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt-mit8", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv-mit8", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdb5-6", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.10.1+dfsg-5+deb7u2", rls:"DEB7"))) {
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
