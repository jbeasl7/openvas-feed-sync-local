# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882987");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2018-15911", "CVE-2018-16541", "CVE-2018-16802",
                "CVE-2018-17183", "CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284",
                "CVE-2018-19134", "CVE-2018-19409");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-12-19 10:08:29 +0100 (Wed, 19 Dec 2018)");
  script_name("CentOS Update for ghostscript CESA-2018:3834 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2018:3834");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-December/023134.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the CESA-2018:3834 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Ghostscript suite contains utilities for rendering PostScript and PDF
documents. Ghostscript translates PostScript code to common bitmap formats
so that the code can be displayed or printed.

Security Fix(es):

  * ghostscript: Incorrect free logic in pagedevice replacement (699664)
(CVE-2018-16541)

  * ghostscript: Incorrect 'restoration of privilege' checking when running
out of stack during exception handling (CVE-2018-16802)

  * ghostscript: User-writable error exception table (CVE-2018-17183)

  * ghostscript: Saved execution stacks can leak operator arrays (incomplete
fix for CVE-2018-17183) (CVE-2018-17961)

  * ghostscript: Saved execution stacks can leak operator arrays
(CVE-2018-18073)

  * ghostscript: 1Policy operator allows a sandbox protection bypass
(CVE-2018-18284)

  * ghostscript: Type confusion in setpattern (700141) (CVE-2018-19134)

  * ghostscript: Improperly implemented security check in zsetdevice function
in psi/zdevice.c (CVE-2018-19409)

  * ghostscript: Uninitialized memory access in the aesdecode operator
(699665) (CVE-2018-15911)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Tavis Ormandy (Google Project Zero) for
reporting CVE-2018-16541.

Bug Fix(es):

  * It has been found that ghostscript-9.07-31.el7_6.1 introduced regression
during the handling of shading objects, causing a 'Dropping incorrect
smooth shading object' warning. With this update, the regression has been
fixed and the described problem no longer occurs. (BZ#1657822)");

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

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~31.el7_6.6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-cups", rpm:"ghostscript-cups~9.07~31.el7_6.6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.07~31.el7_6.6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.07~31.el7_6.6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~9.07~31.el7_6.6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
