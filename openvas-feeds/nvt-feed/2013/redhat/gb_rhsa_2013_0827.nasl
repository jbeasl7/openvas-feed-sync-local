# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.870997");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-05-17 09:50:31 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-2053");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for openswan RHSA-2013:0827-01");

  script_xref(name:"RHSA", value:"2013:0827-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-May/msg00013.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openswan'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");
  script_tag(name:"affected", value:"openswan on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Openswan is a free implementation of Internet Protocol Security (IPsec)
  and Internet Key Exchange (IKE). IPsec uses strong cryptography to provide
  both authentication and encryption services. These services allow you to
  build secure tunnels through untrusted networks. When using Opportunistic
  Encryption, Openswan's pluto IKE daemon requests DNS TXT records to obtain
  public RSA keys of itself and its peers.

  A buffer overflow flaw was found in Openswan. If Opportunistic Encryption
  were enabled (oe=yes in /etc/ipsec.conf) and an RSA key configured, an
  attacker able to cause a system to perform a DNS lookup for an
  attacker-controlled domain containing malicious records (such as by sending
  an email that triggers a DKIM or SPF DNS record lookup) could cause
  Openswan's pluto IKE daemon to crash or, potentially, execute arbitrary
  code with root privileges. With oe=yes but no RSA key configured, the
  issue can only be triggered by attackers on the local network who can
  control the reverse DNS entry of the target system. Opportunistic
  Encryption is disabled by default. (CVE-2013-2053)

  This issue was discovered by Florian Weimer of the Red Hat Product Security
  Team.

  All users of openswan are advised to upgrade to these updated packages,
  which contain backported patches to correct this issue. After installing
  this update, the ipsec service will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openswan", rpm:"openswan~2.6.32~20.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openswan-debuginfo", rpm:"openswan-debuginfo~2.6.32~20.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"openswan", rpm:"openswan~2.6.32~5.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openswan-debuginfo", rpm:"openswan-debuginfo~2.6.32~5.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openswan-doc", rpm:"openswan-doc~2.6.32~5.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
