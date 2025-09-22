# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881797");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-24 11:45:25 +0530 (Tue, 24 Sep 2013)");
  script_cve_id("CVE-2013-4324");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for spice-glib CESA-2013:1273 centos6");

  script_tag(name:"affected", value:"spice-glib on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
(Simple Protocol for Independent Computing Environments) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of this
widget to access virtual machines using the SPICE protocol.

spice-gtk communicated with PolicyKit for authorization via an API that is
vulnerable to a race condition. This could lead to intended PolicyKit
authorizations being bypassed. This update modifies spice-gtk to
communicate with PolicyKit via a different API that is not vulnerable to
the race condition. (CVE-2013-4324)

All users of spice-gtk are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1273");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-September/019950.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-glib'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"spice-glib", rpm:"spice-glib~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-glib-devel", rpm:"spice-glib-devel~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-devel", rpm:"spice-gtk-devel~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-python", rpm:"spice-gtk-python~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-tools", rpm:"spice-gtk-tools~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
