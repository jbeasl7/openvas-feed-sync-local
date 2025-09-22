# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871447");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-09-04 08:13:22 +0200 (Fri, 04 Sep 2015)");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libXfont RHSA-2015:1708-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory.");
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
  script_tag(name:"affected", value:"libXfont on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1708-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-September/msg00006.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.7~3.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.4.7~3.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.5~5.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.4.5~5.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
