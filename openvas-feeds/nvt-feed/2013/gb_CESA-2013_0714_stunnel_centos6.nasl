# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881712");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-15 10:13:31 +0530 (Mon, 15 Apr 2013)");
  script_cve_id("CVE-2013-1762");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:C");
  script_name("CentOS Update for stunnel CESA-2013:0714 centos6");

  script_xref(name:"CESA", value:"2013:0714");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-April/019681.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'stunnel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"stunnel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"stunnel is a socket wrapper which can provide SSL (Secure Sockets Layer)
  support to ordinary applications. For example, it can be used in
  conjunction with imapd to create an SSL-secure IMAP server.

  An integer conversion issue was found in stunnel when using Microsoft NT
  LAN Manager (NTLM) authentication with the HTTP CONNECT tunneling method.
  With this configuration, and using stunnel in SSL client mode on a 64-bit
  system, an attacker could possibly execute arbitrary code with the
  privileges of the stunnel process via a man-in-the-middle attack or by
  tricking a user into using a malicious proxy. (CVE-2013-1762)

  All stunnel users should upgrade to this updated package, which contains a
  backported patch to correct this issue.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~4.29~3.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
