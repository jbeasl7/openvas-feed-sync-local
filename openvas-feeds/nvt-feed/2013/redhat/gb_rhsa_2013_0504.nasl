# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00047.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55530");
  script_oid("1.3.6.1.4.1.25623.1.0.870920");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:39 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-3955");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_xref(name:"RHSA", value:"2013:0504-02");
  script_name("RedHat Update for dhcp RHSA-2013:0504-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"dhcp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The dhcp packages provide the Dynamic Host Configuration Protocol (DHCP)
  that allows individual devices on an IP network to get their own network
  configuration information, including an IP address, a subnet mask, and a
  broadcast address.

  A flaw was found in the way the dhcpd daemon handled the expiration time of
  IPv6 leases. If dhcpd's configuration was changed to reduce the default
  IPv6 lease time, lease renewal requests for previously assigned leases
  could cause dhcpd to crash. (CVE-2012-3955)

  This update also fixes the following bugs:

  * Prior to this update, the DHCP server discovered only the first IP
  address of a network interface if the network interface had more than one
  configured IP address. As a consequence, the DHCP server failed to
  restart if the server was configured to serve only a subnet of the
  following IP addresses. This update modifies network interface addresses
  discovery code to find all addresses of a network interface. The DHCP
  server can also serve subnets of other addresses. (BZ#803540)

  * Prior to this update, the dhclient rewrote the /etc/resolv.conf file
  with backup data after it was stopped even when the PEERDNS flag was set
  to no before shut down if the configuration file was changed while the
  dhclient ran with PEERDNS=yes. This update removes the backing up and
  restoring functions for this configuration file from the dhclient-script.
  Now, the dhclient no longer rewrites the /etc/resolv.conf file when
  stopped. (BZ#824622)

  All users of DHCP are advised to upgrade to these updated packages, which
  fix these issues. After installing this update, all DHCP servers will be
  restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"dhclient", rpm:"dhclient~4.1.1~34.P1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.1.1~34.P1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~4.1.1~34.P1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp-debuginfo", rpm:"dhcp-debuginfo~4.1.1~34.P1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
