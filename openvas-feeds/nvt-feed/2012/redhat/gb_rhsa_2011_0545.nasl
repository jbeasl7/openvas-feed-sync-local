# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00015.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870666");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:44:53 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3072");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2011:0545-01");
  script_name("RedHat Update for squid RHSA-2011:0545-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"squid on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Squid is a high-performance proxy caching server for web clients,
  supporting FTP, Gopher, and HTTP data objects.

  It was found that string comparison functions in Squid did not properly
  handle the comparisons of NULL and empty strings. A remote, trusted web
  client could use this flaw to cause the squid daemon to crash via a
  specially-crafted request. (CVE-2010-3072)

  This update also fixes the following bugs:

  * A small memory leak in Squid caused multiple 'ctx: enter level' messages
  to be logged to '/var/log/squid/cache.log'. This update resolves the memory
  leak. (BZ#666533)

  * This erratum upgrades Squid to upstream version 3.1.10. This upgraded
  version supports the Google Instant service and introduces various code
  improvements. (BZ#639365)

  Users of squid should upgrade to this updated package, which resolves these
  issues. After installing this update, the squid service will be restarted
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

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.1.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.1.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
