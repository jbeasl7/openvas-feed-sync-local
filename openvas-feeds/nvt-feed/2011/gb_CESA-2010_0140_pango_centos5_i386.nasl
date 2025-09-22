# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016560.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880607");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2010:0140");
  script_cve_id("CVE-2010-0421");
  script_name("CentOS Update for pango CESA-2010:0140 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pango'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"pango on CentOS 5");
  script_tag(name:"insight", value:"Pango is a library used for the layout and rendering of internationalized
  text.

  An input sanitization flaw, leading to an array index error, was found in
  the way the Pango font rendering library synthesized the Glyph Definition
  (GDEF) table from a font's character map and the Unicode property database.
  If an attacker created a specially-crafted font file and tricked a local,
  unsuspecting user into loading the font file in an application that uses
  the Pango font rendering library, it could cause that application to crash.
  (CVE-2010-0421)

  Users of pango and evolution28-pango are advised to upgrade to these
  updated packages, which contain a backported patch to resolve this issue.
  After installing this update, you must restart your system or restart your
  X session for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.14.9~8.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.14.9~8.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
