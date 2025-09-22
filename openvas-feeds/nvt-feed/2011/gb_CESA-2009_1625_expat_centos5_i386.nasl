# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-December/016378.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880786");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2009:1625");
  script_cve_id("CVE-2009-3560", "CVE-2009-3720");
  script_name("CentOS Update for expat CESA-2009:1625 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"expat on CentOS 5");
  script_tag(name:"insight", value:"Expat is a C library written by James Clark for parsing XML documents.

  Two buffer over-read flaws were found in the way Expat handled malformed
  UTF-8 sequences when processing XML files. A specially-crafted XML file
  could cause applications using Expat to crash while parsing the file.
  (CVE-2009-3560, CVE-2009-3720)

  All expat users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, applications using the Expat library must be restarted for the
  update to take effect.");
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

  if ((res = isrpmvuln(pkg:"expat", rpm:"expat~1.95.8~8.3.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expat-devel", rpm:"expat-devel~1.95.8~8.3.el5_4.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
