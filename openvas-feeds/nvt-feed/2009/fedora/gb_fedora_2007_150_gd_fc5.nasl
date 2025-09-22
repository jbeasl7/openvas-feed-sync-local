# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-February/msg00080.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861154");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 15:48:41 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"FEDORA", value:"2007-150");
  script_cve_id("CVE-2007-0455");
  script_name("Fedora Update for gd FEDORA-2007-150");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC5");

  script_tag(name:"affected", value:"gd on Fedora Core 5");
  script_tag(name:"solution", value:"Please install the updated package(s).");

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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/gd-debuginfo", rpm:"x86_64/debug/gd-debuginfo~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/gd-progs", rpm:"x86_64/gd-progs~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/gd-devel", rpm:"x86_64/gd-devel~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/gd", rpm:"x86_64/gd~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/gd-progs", rpm:"i386/gd-progs~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/gd-debuginfo", rpm:"i386/debug/gd-debuginfo~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/gd-devel", rpm:"i386/gd-devel~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/gd", rpm:"i386/gd~2.0.33~7.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}