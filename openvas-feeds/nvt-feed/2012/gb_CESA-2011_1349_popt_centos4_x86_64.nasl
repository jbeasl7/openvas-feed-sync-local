# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-November/018160.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881411");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:48:59 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3378");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:1349");
  script_name("CentOS Update for popt CESA-2011:1349 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'popt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"popt on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The RPM Package Manager (RPM) is a command line driven package management
  system capable of installing, uninstalling, verifying, querying, and
  updating software packages.

  Multiple flaws were found in the way the RPM library parsed package
  headers. An attacker could create a specially-crafted RPM package that,
  when queried or installed, would cause rpm to crash or, potentially,
  execute arbitrary code. (CVE-2011-3378)

  Note: Although an RPM package can, by design, execute arbitrary code when
  installed, this issue would allow a specially-crafted RPM package to
  execute arbitrary code before its digital signature has been verified.
  Package downloads from the Red Hat Network remain secure due to certificate
  checks performed on the secure connection.

  All RPM users should upgrade to these updated packages, which contain a
  backported patch to correct these issues. All running applications linked
  against the RPM library must be restarted for this update to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"popt", rpm:"popt~1.9.1~35_nonptl.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.3.3~35_nonptl.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.3.3~35_nonptl.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.3.3~35_nonptl.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-libs", rpm:"rpm-libs~4.3.3~35_nonptl.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.3.3~35_nonptl.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
