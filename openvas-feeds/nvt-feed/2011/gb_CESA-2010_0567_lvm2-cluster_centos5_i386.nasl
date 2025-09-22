# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-July/016844.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880581");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0567");
  script_cve_id("CVE-2010-2526");
  script_name("CentOS Update for lvm2-cluster CESA-2010:0567 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lvm2-cluster'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"lvm2-cluster on CentOS 5");
  script_tag(name:"insight", value:"The lvm2-cluster package contains support for Logical Volume Management
  (LVM) in a clustered environment.

  It was discovered that the cluster logical volume manager daemon (clvmd)
  did not verify the credentials of clients connecting to its control UNIX
  abstract socket, allowing local, unprivileged users to send control
  commands that were intended to only be available to the privileged root
  user. This could allow a local, unprivileged user to cause clvmd to exit,
  or request clvmd to activate, deactivate, or reload any logical volume on
  the local system or another system in the cluster. (CVE-2010-2526)

  Note: This update changes clvmd to use a pathname-based socket rather than
  an abstract socket. As such, the lvm2 update RHBA-2010:0569, which changes
  LVM to also use this pathname-based socket, must also be installed for LVM
  to be able to communicate with the updated clvmd.

  All lvm2-cluster users should upgrade to this updated package, which
  contains a backported patch to correct this issue. After installing the
  updated package, clvmd must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"lvm2-cluster", rpm:"lvm2-cluster~2.02.56~7.el5_5.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
