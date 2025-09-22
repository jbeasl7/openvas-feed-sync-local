# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-December/018342.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881261");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:13:28 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4516", "CVE-2011-4517");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:1807");
  script_name("CentOS Update for jasper CESA-2011:1807 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"jasper on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"JasPer is an implementation of Part 1 of the JPEG 2000 image compression
  standard.

  Two heap-based buffer overflow flaws were found in the way JasPer decoded
  JPEG 2000 compressed image files. An attacker could create a malicious JPEG
  2000 compressed image file that, when opened, would cause applications that
  use JasPer (such as Nautilus) to crash or, potentially, execute arbitrary
  code. (CVE-2011-4516, CVE-2011-4517)

  Red Hat would like to thank Jonathan Foote of the CERT Coordination Center
  for reporting these issues.

  Users are advised to upgrade to these updated packages, which contain a
  backported patch to correct these issues. All applications using the JasPer
  libraries (such as Nautilus) must be restarted for the update to take
  effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~15.el6_1.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-devel", rpm:"jasper-devel~1.900.1~15.el6_1.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~15.el6_1.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-utils", rpm:"jasper-utils~1.900.1~15.el6_1.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
