# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016128.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880936");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name:"CESA", value:"2009:1427");
  script_cve_id("CVE-2007-4565", "CVE-2008-2711", "CVE-2009-2666");
  script_name("CentOS Update for fetchmail CESA-2009:1427 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fetchmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"fetchmail on CentOS 4");
  script_tag(name:"insight", value:"Fetchmail is a remote mail retrieval and forwarding utility intended for
  use over on-demand TCP/IP links, such as SLIP and PPP connections.

  It was discovered that fetchmail is affected by the previously published
  'null prefix attack', caused by incorrect handling of NULL characters in
  X.509 certificates. If an attacker is able to get a carefully-crafted
  certificate signed by a trusted Certificate Authority, the attacker could
  use the certificate during a man-in-the-middle attack and potentially
  confuse fetchmail into accepting it by mistake. (CVE-2009-2666)

  A flaw was found in the way fetchmail handles rejections from a remote SMTP
  server when sending warning mail to the postmaster. If fetchmail sent a
  warning mail to the postmaster of an SMTP server and that SMTP server
  rejected it, fetchmail could crash. (CVE-2007-4565)

  A flaw was found in fetchmail. When fetchmail is run in double verbose
  mode ('-v -v'), it could crash upon receiving certain, malformed mail
  messages with long headers. A remote attacker could use this flaw to cause
  a denial of service if fetchmail was also running in daemon mode ('-d').
  (CVE-2008-2711)

  Note: when using SSL-enabled services, it is recommended that the fetchmail
  '--sslcertck' option be used to enforce strict SSL certificate checking.

  All fetchmail users should upgrade to this updated package, which contains
  backported patches to correct these issues. If fetchmail is running in
  daemon mode, it must be restarted for this update to take effect (use the
  'fetchmail --quit' command to stop the fetchmail process).");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"fetchmail", rpm:"fetchmail~6.2.5~6.0.1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
