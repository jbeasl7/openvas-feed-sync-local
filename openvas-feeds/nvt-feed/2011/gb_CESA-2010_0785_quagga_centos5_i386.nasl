# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-October/017097.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880606");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0785");
  script_cve_id("CVE-2007-4826", "CVE-2010-2948");
  script_name("CentOS Update for quagga CESA-2010:0785 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"quagga on CentOS 5");
  script_tag(name:"insight", value:"Quagga is a TCP/IP based routing software suite. The Quagga bgpd daemon
  implements the BGP (Border Gateway Protocol) routing protocol.

  A stack-based buffer overflow flaw was found in the way the Quagga bgpd
  daemon processed certain BGP Route Refresh (RR) messages. A configured BGP
  peer could send a specially-crafted BGP message, causing bgpd on a target
  system to crash or, possibly, execute arbitrary code with the privileges of
  the user running bgpd. (CVE-2010-2948)

  Note: On Red Hat Enterprise Linux 5 it is not possible to exploit
  CVE-2010-2948 to run arbitrary code as the overflow is blocked by
  FORTIFY_SOURCE.

  Multiple NULL pointer dereference flaws were found in the way the Quagga
  bgpd daemon processed certain specially-crafted BGP messages. A configured
  BGP peer could crash bgpd on a target system via specially-crafted BGP
  messages. (CVE-2007-4826)

  Users of quagga should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the bgpd daemon must be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.98.6~5.el5_5.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.98.6~5.el5_5.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.98.6~5.el5_5.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
