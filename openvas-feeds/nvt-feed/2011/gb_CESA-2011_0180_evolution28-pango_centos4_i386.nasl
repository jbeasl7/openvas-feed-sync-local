# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-February/017249.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880472");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0180");
  script_cve_id("CVE-2011-0020");
  script_name("CentOS Update for evolution28-pango CESA-2011:0180 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution28-pango'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"evolution28-pango on CentOS 4");
  script_tag(name:"insight", value:"Pango is a library used for the layout and rendering of internationalized
  text.

  An input sanitization flaw, leading to a heap-based buffer overflow, was
  found in the way Pango displayed font files when using the FreeType font
  engine back end. If a user loaded a malformed font file with an application
  that uses Pango, it could cause the application to crash or, possibly,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-0020)

  Users of pango and evolution28-pango are advised to upgrade to these
  updated packages, which contain a backported patch to resolve this issue.
  After installing the updated packages, you must restart your system or
  restart your X session for the update to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"evolution28-pango", rpm:"evolution28-pango~1.14.9~13.el4_10", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-pango-devel", rpm:"evolution28-pango-devel~1.14.9~13.el4_10", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
