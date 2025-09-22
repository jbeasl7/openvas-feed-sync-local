# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871483");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-20 06:19:59 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-3455");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for squid RHSA-2015:2378-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

It was found that Squid configured with client-first SSL-bump did not
correctly validate X.509 server certificate host name fields. A
man-in-the-middle attacker could use this flaw to spoof a Squid server
using a specially crafted X.509 certificate. (CVE-2015-3455)

This update fixes the following bugs:

  * Previously, the squid process did not handle file descriptors correctly
when receiving Simple Network Management Protocol (SNMP) requests. As a
consequence, the process gradually accumulated open file descriptors. This
bug has been fixed and squid now handles SNMP requests correctly, closing
file descriptors when necessary. (BZ#1198778)

  * Under high system load, the squid process sometimes terminated
unexpectedly with a segmentation fault during reboot. This update provides
better memory handling during reboot, thus fixing this bug. (BZ#1225640)

Users of squid are advised to upgrade to these updated packages, which fix
these bugs. After installing this update, the squid service will be
restarted automatically.");
  script_tag(name:"affected", value:"squid on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2378-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00043.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.3.8~26.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.3.8~26.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
