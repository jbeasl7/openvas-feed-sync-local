# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882276");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-04 08:14:55 +0200 (Fri, 04 Sep 2015)");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libXfont CESA-2015:1708 centos7");
  script_tag(name:"summary", value:"Check the version of libXfont");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libXfont package provides the X.Org libXfont runtime library. X.Org is
an open source implementation of the X Window System.

An integer overflow flaw was found in the way libXfont processed certain
Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could
use this flaw to crash the X.Org server or, potentially, execute arbitrary
code with the privileges of the X.Org server. (CVE-2015-1802)

An integer truncation flaw was discovered in the way libXfont processed
certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local
user could use this flaw to crash the X.Org server or, potentially, execute
arbitrary code with the privileges of the X.Org server. (CVE-2015-1804)

A NULL pointer dereference flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts.
A malicious, local user could use this flaw to crash the X.Org server.
(CVE-2015-1803)

All libXfont users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"affected", value:"libXfont on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1708");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-September/021371.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.7~3.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.7~3.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
