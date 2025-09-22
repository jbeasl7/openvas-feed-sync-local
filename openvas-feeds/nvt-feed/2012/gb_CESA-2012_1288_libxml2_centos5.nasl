# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-September/018891.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881507");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-22 11:58:35 +0530 (Sat, 22 Sep 2012)");
  script_cve_id("CVE-2011-3102", "CVE-2012-2807");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:1288");
  script_name("CentOS Update for libxml2 CESA-2012:1288 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libxml2 on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libxml2 library is a development toolbox providing the implementation
  of various XML standards.

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way libxml2 handled documents that enable entity
  expansion. A remote attacker could provide a large, specially-crafted XML
  file that, when opened in an application linked against libxml2, would
  cause the application to crash or, potentially, execute arbitrary code with
  the privileges of the user running the application. (CVE-2012-2807)

  A one byte buffer overflow was found in the way libxml2 evaluated certain
  parts of XML Pointer Language (XPointer) expressions. A remote attacker
  could provide a specially-crafted XML file that, when opened in an
  application linked against libxml2, would cause the application to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2011-3102)

  All users of libxml2 are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. The desktop must
  be restarted (log out, then log back in) for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.15.el5_8.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.15.el5_8.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.15.el5_8.5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
