# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018417.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881141");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:21:25 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4054", "CVE-2010-4820");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:0096");
  script_name("CentOS Update for ghostscript CESA-2012:0096 centos4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"ghostscript on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Ghostscript is a set of software that provides a PostScript interpreter, a
  set of C procedures (the Ghostscript library, which implements the graphics
  capabilities in the PostScript language) and an interpreter for Portable
  Document Format (PDF) files.

  Ghostscript included the current working directory in its library search
  path by default. If a user ran Ghostscript without the '-P-' option in an
  attacker-controlled directory containing a specially-crafted PostScript
  library file, it could cause Ghostscript to execute arbitrary PostScript
  code. With this update, Ghostscript no longer searches the current working
  directory for library files by default. (CVE-2010-4820)

  Note: The fix for CVE-2010-4820 could possibly break existing
  configurations. To use the previous, vulnerable behavior, run Ghostscript
  with the '-P' option (to always search the current working directory
  first).

  A flaw was found in the way Ghostscript interpreted PostScript Type 1 and
  PostScript Type 2 font files. An attacker could create a specially-crafted
  PostScript Type 1 or PostScript Type 2 font file that, when interpreted,
  could cause Ghostscript to crash or, potentially, execute arbitrary code.
  (CVE-2010-4054)

  Users of Ghostscript are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~7.07~33.13.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~7.07~33.13.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~7.07~33.13.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
