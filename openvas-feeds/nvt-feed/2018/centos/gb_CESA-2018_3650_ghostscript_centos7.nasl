# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882976");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2018-15908", "CVE-2018-15909", "CVE-2018-16511", "CVE-2018-16539");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-12-18 07:37:15 +0100 (Tue, 18 Dec 2018)");
  script_name("CentOS Update for ghostscript CESA-2018:3650 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2018:3650");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-December/023100.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the CESA-2018:3650 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Ghostscript suite contains utilities for rendering PostScript and PDF
documents. Ghostscript translates PostScript code to common bitmap formats
so that the code can be displayed or printed.

Security Fix(es):

  * ghostscript: .tempfile file permission issues (699657) (CVE-2018-15908)

  * ghostscript: shading_param incomplete type checking (699660)
(CVE-2018-15909)

  * ghostscript: missing type check in type checker (699659) (CVE-2018-16511)

  * ghostscript: incorrect access checking in temp file handling to disclose
contents of files (699658) (CVE-2018-16539)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Tavis Ormandy (Google Project Zero) for
reporting CVE-2018-15908.");

  script_tag(name:"affected", value:"ghostscript on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~31.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-cups", rpm:"ghostscript-cups~9.07~31.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.07~31.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.07~31.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~9.07~31.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
