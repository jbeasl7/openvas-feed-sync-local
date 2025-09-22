# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881944");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-09 12:29:43 +0530 (Mon, 09 Jun 2014)");
  script_cve_id("CVE-2014-0224");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");
  script_name("CentOS Update for openssl098e CESA-2014:0626 centos6");

  script_tag(name:"affected", value:"openssl098e on CentOS 6");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer
(SSL v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was found that OpenSSL clients and servers could be forced, via a
specially crafted handshake packet, to use weak keying material for
communication. A man-in-the-middle attacker could use this flaw to decrypt
and modify traffic between a client and a server. (CVE-2014-0224)

Note: In order to exploit this flaw, both the server and the client must be
using a vulnerable version of OpenSSL  the server must be using OpenSSL
version 1.0.1 and above, and the client must be using any version of
OpenSSL. Please see the references for more information about this flaw.

Red Hat would like to thank the OpenSSL project for reporting this issue.
Upstream acknowledges KIKUCHI Masashi of Lepidum as the original reporter
of this issue.

All OpenSSL users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to take
effect, all services linked to the OpenSSL library (such as httpd and other
SSL-enabled services) must be restarted or the system rebooted.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to
use the Red Hat Network to apply this update are available at the
linked references.

5. Bugs fixed:

1103586 - CVE-2014-0224 openssl: SSL/TLS MITM vulnerability

6. Package List:

Red Hat Enterprise Linux Desktop (v. 5 client):

Source:
openssl097a-0.9.7a-12.el5_10.1.src.rpm

i386:
openssl097a-0.9.7a-12.el5_10.1.i386.rpm
openssl097a-debuginfo-0.9.7a-12.el5_10.1.i386.rpm

x86_64:
openssl097a-0.9.7a-12.el5_10.1.i386.rpm
openssl097a-0.9.7a-12.el5_10.1.x86_64.rpm
openssl097a-debuginfo-0.9.7a-12.el5_10.1.i386.rpm
openssl097a-debuginfo-0.9.7a-12.el5_10.1.x86_64.rpm

Red Hat Enterprise Linux (v. 5 server):

Source:
openssl097a-0.9.7a-12.el5_10.1.src.rpm

i386:
openssl097a-0.9.7a-12.el5_10.1.i386.rpm
openssl097a-debuginfo-0.9.7a-12.el5_10.1.i386.rpm

ia64:
openssl097a-0.9.7a-12.el5_10.1.i386.rpm
openssl097a-0.9.7a-12.el5_10.1.ia64.rpm
openssl097a-debuginfo-0.9.7a-12.el5_10.1.i386.rpm
openssl097a-debuginfo-0.9.7a-12.el5_10.1.ia6 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0626");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-June/020345.html");
  script_xref(name:"URL", value:"https://access.redhat.com/site/articles/11258");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl098e'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_xref(name:"URL", value:"https://access.redhat.com/site/articles/904433");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~18.el6_5.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
