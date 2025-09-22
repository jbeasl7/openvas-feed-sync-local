# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-June/018700.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881106");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:09:14 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2149");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:1043");
  script_name("CentOS Update for libwpd CESA-2012:1043 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libwpd on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"libwpd is a library for reading and converting Corel WordPerfect Office
  documents.

  A buffer overflow flaw was found in the way libwpd processed certain
  Corel WordPerfect Office documents (.wpd files). An attacker could provide
  a specially-crafted .wpd file that, when opened in an application linked
  against libwpd, such as OpenOffice.org, would cause the application to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2012-2149)

  All libwpd users are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running applications
  that are linked against libwpd must be restarted for this update to take
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libwpd", rpm:"libwpd~0.8.7~3.1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd-devel", rpm:"libwpd-devel~0.8.7~3.1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd-tools", rpm:"libwpd-tools~0.8.7~3.1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
