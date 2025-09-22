# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-January/017236.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881366");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:36:42 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2008-7270", "CVE-2009-3245", "CVE-2010-4180");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0977");
  script_name("CentOS Update for openssl CESA-2010:0977 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"openssl on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  A ciphersuite downgrade flaw was found in the OpenSSL SSL/TLS server code.
  A remote attacker could possibly use this flaw to change the ciphersuite
  associated with a cached session stored on the server, if the server
  enabled the SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option, possibly
  forcing the client to use a weaker ciphersuite after resuming the session.
  (CVE-2010-4180, CVE-2008-7270)

  Note: With this update, setting the SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  option has no effect and this bug workaround can no longer be enabled.

  It was discovered that OpenSSL did not always check the return value of the
  bn_wexpand() function. An attacker able to trigger a memory allocation
  failure in that function could possibly crash an application using the
  OpenSSL library and its UBSEC hardware engine support. (CVE-2009-3245)

  All OpenSSL users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. For the update to take effect,
  all services linked to the OpenSSL library must be restarted, or the system
  rebooted.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.7a~43.17.el4_8.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.7a~43.17.el4_8.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.7a~43.17.el4_8.6", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
