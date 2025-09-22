# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882202");
  script_version("2023-07-11T05:06:07+0000");
  script_cve_id("CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-19 06:18:37 +0200 (Fri, 19 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for cups CESA-2015:1123 centos6");
  script_tag(name:"summary", value:"Check the version of cups");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"CUPS provides a portable printing layer
  for Linux, UNIX, and similar operating systems.

A string reference count bug was found in cupsd, causing premature freeing
of string objects. An attacker can submit a malicious print job that
exploits this flaw to dismantle ACLs protecting privileged operations,
allowing a replacement configuration file to be uploaded which in turn
allows the attacker to run arbitrary code in the CUPS server
(CVE-2015-1158)

A cross-site scripting flaw was found in the cups web templating engine. An
attacker could use this flaw to bypass the default configuration settings
that bind the CUPS scheduler to the 'localhost' or loopback interface.
(CVE-2015-1159)

An integer overflow leading to a heap-based buffer overflow was found in
the way cups handled compressed raster image files. An attacker could
create a specially-crafted image file, which when passed via the cups
Raster filter, could cause the cups filter to crash. (CVE-2014-9679)

Red Hat would like to thank the CERT/CC for reporting CVE-2015-1158 and
CVE-2015-1159 issues.

All cups users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the cupsd daemon will be restarted automatically.");
  script_tag(name:"affected", value:"cups on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1123");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-June/021179.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.2~67.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.4.2~67.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.4.2~67.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.4.2~67.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-php", rpm:"cups-php~1.4.2~67.el6_6.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
