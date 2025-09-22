# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881855");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-23 12:48:25 +0530 (Mon, 23 Dec 2013)");
  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for openjpeg CESA-2013:1850 centos6");

  script_tag(name:"affected", value:"openjpeg on CentOS 6");
  script_tag(name:"insight", value:"OpenJPEG is an open source library for reading and writing image files in
JPEG 2000 format.

Multiple heap-based buffer overflow flaws were found in OpenJPEG.
An attacker could create a specially crafted OpenJPEG image that, when
opened, could cause an application using openjpeg to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2013-6045, CVE-2013-6054)

Multiple denial of service flaws were found in OpenJPEG. An attacker could
create a specially crafted OpenJPEG image that, when opened, could cause an
application using openjpeg to crash (CVE-2013-1447, CVE-2013-6052)

Red Hat would like to thank Raphael Geissert for reporting these issues.

Users of OpenJPEG are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications using OpenJPEG must be restarted for the update to take
effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1850");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020079.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg'
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

  if ((res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.3~10.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-devel", rpm:"openjpeg-devel~1.3~10.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-libs", rpm:"openjpeg-libs~1.3~10.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}