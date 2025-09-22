# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-May/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870691");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 10:47:31 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2012-2134");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2012:0683-01");
  script_name("RedHat Update for bind-dyndb-ldap RHSA-2012:0683-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind-dyndb-ldap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"bind-dyndb-ldap on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The dynamic LDAP back end is a plug-in for BIND that provides back-end
  capabilities to LDAP databases. It features support for dynamic updates
  and internal caching that help to reduce the load on LDAP servers.

  A flaw was found in the way bind-dyndb-ldap handled LDAP query errors. If a
  remote attacker were able to send DNS queries to a named server that is
  configured to use bind-dyndb-ldap, they could trigger such an error with a
  DNS query leveraging bind-dyndb-ldap's insufficient escaping of the LDAP
  base DN (distinguished name). This would result in an invalid LDAP query
  that named would retry in a loop, preventing it from responding to other
  DNS queries. With this update, bind-dyndb-ldap only attempts to retry one
  time when an LDAP search returns an unexpected error. (CVE-2012-2134)

  Red Hat would like to thank Ronald van Zantvoort for reporting this issue.

  All bind-dyndb-ldap users should upgrade to this updated package, which
  contains a backported patch to correct this issue. For the update to take
  effect, the named service must be restarted.");
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

  if ((res = isrpmvuln(pkg:"bind-dyndb-ldap", rpm:"bind-dyndb-ldap~0.2.0~7.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-dyndb-ldap-debuginfo", rpm:"bind-dyndb-ldap-debuginfo~0.2.0~7.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
