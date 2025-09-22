# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871353");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-04-14 07:17:13 +0200 (Tue, 14 Apr 2015)");
  script_cve_id("CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0287", "CVE-2015-0288",
                "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssl RHSA-2015:0800-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was discovered that OpenSSL would accept ephemeral RSA keys when using
non-export RSA cipher suites. A malicious server could make a TLS/SSL
client using OpenSSL use a weaker key exchange method. (CVE-2015-0204)

An integer underflow flaw, leading to a buffer overflow, was found in the
way OpenSSL decoded malformed Base64-encoded inputs. An attacker able to
make an application using OpenSSL decode a specially crafted Base64-encoded
input (such as a PEM file) could use this flaw to cause the application to
crash. Note: this flaw is not exploitable via the TLS/SSL protocol because
the data being transferred is not Base64-encoded. (CVE-2015-0292)

A denial of service flaw was found in the way OpenSSL handled SSLv2
handshake messages. A remote attacker could use this flaw to cause a
TLS/SSL server using OpenSSL to exit on a failed assertion if it had both
the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293)

Multiple flaws were found in the way OpenSSL parsed X.509 certificates.
An attacker could use these flaws to modify an X.509 certificate to produce
a certificate with a different fingerprint without invalidating its
signature, and possibly bypass fingerprint-based blacklisting in
applications. (CVE-2014-8275)

An out-of-bounds write flaw was found in the way OpenSSL reused certain
ASN.1 structures. A remote attacker could possibly use a specially crafted
ASN.1 structure that, when parsed by an application, would cause that
application to crash. (CVE-2015-0287)

A NULL pointer dereference flaw was found in OpenSSL's X.509 certificate
handling implementation. A specially crafted X.509 certificate could cause
an application using OpenSSL to crash if the application attempted to
convert the certificate to a certificate request. (CVE-2015-0288)

A NULL pointer dereference was found in the way OpenSSL handled certain
PKCS#7 inputs. An attacker able to make an application using OpenSSL
verify, decrypt, or parse a specially crafted PKCS#7 input could cause that
application to crash. TLS/SSL clients and servers using OpenSSL were not
affected by this flaw. (CVE-2015-0289)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2015-0287, CVE-2015-0288, CVE-2015-0289, CVE-2015-0292, and
CVE-2015-0293. Upstream acknowledges Emilia Kasper of the OpenSSL
development team as the original reporter of CVE-2015-0287, Brian Carpenter
as the original reporter  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"openssl on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:0800-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-April/msg00016.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~33.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8e~33.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~33.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~33.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
