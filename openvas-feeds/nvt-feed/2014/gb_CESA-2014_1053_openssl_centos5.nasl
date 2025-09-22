# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881987");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-08-14 05:54:51 +0200 (Thu, 14 Aug 2014)");
  script_cve_id("CVE-2014-0221", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3508",
                "CVE-2014-3510");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for openssl CESA-2014:1053 centos5");

  script_tag(name:"affected", value:"openssl on CentOS 5");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer
(SSL), Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose cryptography
library.

It was discovered that the OBJ_obj2txt() function could fail to properly
NUL-terminate its output. This could possibly cause an application using
OpenSSL functions to format fields of X.509 certificates to disclose
portions of its memory. (CVE-2014-3508)

Multiple flaws were discovered in the way OpenSSL handled DTLS packets.
A remote attacker could use these flaws to cause a DTLS server or client
using OpenSSL to crash or use excessive amounts of memory. (CVE-2014-0221,
CVE-2014-3505, CVE-2014-3506)

A NULL pointer dereference flaw was found in the way OpenSSL performed a
handshake when using the anonymous Diffie-Hellman (DH) key exchange. A
malicious server could cause a DTLS client using OpenSSL to crash if that
client had anonymous DH cipher suites enabled. (CVE-2014-3510)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2014-0221. Upstream acknowledges Imre Rad of Search-Lab as the original
reporter of this issue.

All OpenSSL users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. For the update to take
effect, all services linked to the OpenSSL library (such as httpd and other
SSL-enabled services) must be restarted or the system rebooted.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:1053");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020487.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~27.el5_10.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~27.el5_10.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~27.el5_10.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
