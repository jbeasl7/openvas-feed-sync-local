# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00046.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55690");
  script_oid("1.3.6.1.4.1.25623.1.0.870921");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:41 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-4450");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2013:0503-03");
  script_name("RedHat Update for 389-ds-base RHSA-2013:0503-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"389-ds-base on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The 389-ds-base packages provide 389 Directory Server, which is an LDAPv3
  compliant server. The base packages include the Lightweight Directory
  Access Protocol (LDAP) server and command-line utilities for server
  administration.

  A flaw was found in the way 389 Directory Server enforced ACLs after
  performing an LDAP modify relative distinguished name (modrdn) operation.
  After modrdn was used to move part of a tree, the ACLs defined on the moved
  (Distinguished Name) were not properly enforced until the server was
  restarted. This could allow LDAP users to access information that should be
  restricted by the defined ACLs. (CVE-2012-4450)

  This issue was discovered by Noriko Hosoi of Red Hat.

  These updated 389-ds-base packages include numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 6.4
  Technical Notes, linked to in the References, for information on the most
  significant of these changes.

  All users of 389-ds-base are advised to upgrade to these updated packages,
  which correct this issue and provide numerous bug fixes and enhancements.
  After installing this update, the 389 server service will be restarted
  automatically.");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~1.2.11.15~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~11.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
