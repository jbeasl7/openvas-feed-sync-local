# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015880.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880694");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2009:1036");
  script_cve_id("CVE-2009-1574", "CVE-2009-1632");
  script_name("CentOS Update for ipsec-tools CESA-2009:1036 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipsec-tools'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"ipsec-tools on CentOS 5");
  script_tag(name:"insight", value:"The ipsec-tools package is used in conjunction with the IPsec functionality
  in the Linux kernel and includes racoon, an IKEv1 keying daemon.

  A denial of service flaw was found in the ipsec-tools racoon daemon. An
  unauthenticated, remote attacker could trigger a NULL pointer dereference
  that could cause the racoon daemon to crash. (CVE-2009-1574)

  Multiple memory leak flaws were found in the ipsec-tools racoon daemon. If
  a remote attacker is able to make multiple connection attempts to the
  racoon daemon, it was possible to cause the racoon daemon to consume all
  available memory. (CVE-2009-1632)

  Users of ipsec-tools should upgrade to this updated package, which contains
  backported patches to correct these issues. Users must restart the racoon
  daemon for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.6.5~13.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
