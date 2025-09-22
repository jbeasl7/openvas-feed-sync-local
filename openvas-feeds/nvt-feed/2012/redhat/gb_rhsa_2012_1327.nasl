# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-October/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870841");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-10-03 09:21:13 +0530 (Wed, 03 Oct 2012)");
  script_cve_id("CVE-2012-3547");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:1327-01");
  script_name("RedHat Update for freeradius2 RHSA-2012:1327-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"freeradius2 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"FreeRADIUS is a high-performance and highly configurable free Remote
  Authentication Dial In User Service (RADIUS) server, designed to allow
  centralized authentication and authorization for a network.

  A buffer overflow flaw was discovered in the way radiusd handled the
  expiration date field in X.509 client certificates. A remote attacker could
  possibly use this flaw to crash radiusd if it were configured to use the
  certificate or TLS tunnelled authentication methods (such as EAP-TLS,
  EAP-TTLS, and PEAP). (CVE-2012-3547)

  Red Hat would like to thank Timo Warns of PRESENSE Technologies GmbH for
  reporting this issue.

  Users of FreeRADIUS are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, radiusd will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"freeradius2", rpm:"freeradius2~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-debuginfo", rpm:"freeradius2-debuginfo~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-krb5", rpm:"freeradius2-krb5~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-ldap", rpm:"freeradius2-ldap~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-mysql", rpm:"freeradius2-mysql~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-perl", rpm:"freeradius2-perl~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-postgresql", rpm:"freeradius2-postgresql~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-python", rpm:"freeradius2-python~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-unixODBC", rpm:"freeradius2-unixODBC~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-utils", rpm:"freeradius2-utils~2.1.12~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
