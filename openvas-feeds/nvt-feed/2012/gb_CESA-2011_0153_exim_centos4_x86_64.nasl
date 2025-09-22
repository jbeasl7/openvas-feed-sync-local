# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-January/017244.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881419");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-07-30 17:50:06 +0530 (Mon, 30 Jul 2012)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-4345");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:57:37 +0000 (Tue, 16 Jul 2024)");
  script_xref(name:"CESA", value:"2011:0153");
  script_name("CentOS Update for exim CESA-2011:0153 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"exim on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Exim is a mail transport agent (MTA) developed at the University of
  Cambridge for use on UNIX systems connected to the Internet.

  A privilege escalation flaw was discovered in Exim. If an attacker were
  able to gain access to the 'exim' user, they could cause Exim to execute
  arbitrary commands as the root user. (CVE-2010-4345)

  This update adds a new configuration file, '/etc/exim/trusted-configs'. To
  prevent Exim from running arbitrary commands as root, Exim will now drop
  privileges when run with a configuration file not listed as trusted. This
  could break backwards compatibility with some Exim configurations, as the
  trusted-configs file only trusts '/etc/exim/exim.conf' and
  '/etc/exim/exim4.conf' by default. If you are using a configuration file
  not listed in the new trusted-configs file, you will need to add it
  manually.

  Additionally, Exim will no longer allow a user to execute exim as root with
  the -D command line option to override macro definitions. All macro
  definitions that require root permissions must now reside in a trusted
  configuration file.

  Users of Exim are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing this
  update, the exim daemon will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-doc", rpm:"exim-doc~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
