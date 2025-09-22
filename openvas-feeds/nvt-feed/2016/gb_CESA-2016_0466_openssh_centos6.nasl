# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882431");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-03-22 06:12:46 +0100 (Tue, 22 Mar 2016)");
  script_cve_id("CVE-2015-5600", "CVE-2016-3115");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for openssh CESA-2016:0466 centos6");
  script_tag(name:"summary", value:"Check the version of openssh");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell)
protocol implementation. These packages include the core files necessary for
both the OpenSSH client and server.

It was discovered that the OpenSSH server did not sanitize data received
in requests to enable X11 forwarding. An authenticated client with
restricted SSH access could possibly use this flaw to bypass intended
restrictions. (CVE-2016-3115)

It was discovered that the OpenSSH sshd daemon did not check the list of
keyboard-interactive authentication methods for duplicates. A remote
attacker could use this flaw to bypass the MaxAuthTries limit, making it
easier to perform password guessing attacks. (CVE-2015-5600)

All openssh users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the OpenSSH server daemon (sshd) will be restarted automatically.");
  script_tag(name:"affected", value:"openssh on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0466");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021745.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~114.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~114.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~114.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~114.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~114.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~114.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
