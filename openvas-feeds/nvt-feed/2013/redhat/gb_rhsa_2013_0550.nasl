# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00071.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57556");
  script_oid("1.3.6.1.4.1.25623.1.0.870914");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:18 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-5689");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_xref(name:"RHSA", value:"2013:0550-01");
  script_name("RedHat Update for bind RHSA-2013:0550-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"bind on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is an implementation of the
  Domain Name System (DNS) protocols. BIND includes a DNS server (named), a
  resolver library (routines for applications to use when interfacing with
  DNS), and tools for verifying that the DNS server is operating correctly.
  DNS64 is used to automatically generate DNS records so IPv6 based clients
  can access IPv4 systems through a NAT64 server.

  A flaw was found in the DNS64 implementation in BIND when using Response
  Policy Zones (RPZ). If a remote attacker sent a specially-crafted query to
  a named server that is using RPZ rewrite rules, named could exit
  unexpectedly with an assertion failure. Note that DNS64 support is not
  enabled by default. (CVE-2012-5689)

  This update also adds the following enhancement:

  * Previously, it was impossible to configure the maximum number of
  responses sent per second to one client. This allowed remote attackers to
  conduct traffic amplification attacks using DNS queries with spoofed source
  IP addresses. With this update, it is possible to use the new 'rate-limit'
  configuration option in named.conf and configure the maximum number of
  queries which the server responds to. Refer to the BIND documentation for
  more details about the rate-limit option. (BZ#906312)

  All bind users are advised to upgrade to these updated packages, which
  contain patches to correct this issue and add this enhancement. After
  installing the update, the BIND daemon (named) will be restarted
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.2~0.17.rc1.el6.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.8.2~0.17.rc1.el6.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.8.2~0.17.rc1.el6.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.2~0.17.rc1.el6.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.2~0.17.rc1.el6.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
