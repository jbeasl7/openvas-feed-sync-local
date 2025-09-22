# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-January/msg00050.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861500");
  script_version("2023-07-04T05:05:35+0000");
  script_tag(name:"last_modification", value:"2023-07-04 05:05:35 +0000 (Tue, 04 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"FEDORA", value:"2007-036");
  script_cve_id("CVE-2006-1526");
  script_name("Fedora Update for xorg-x11-server FEDORA-2007-036");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC5");

  script_tag(name:"affected", value:"xorg-x11-server on Fedora Core 5");

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

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xdmx", rpm:"x86_64/xorg-x11-server-Xdmx~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xorg", rpm:"x86_64/xorg-x11-server-Xorg~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/xorg-x11-server-debuginfo", rpm:"x86_64/debug/xorg-x11-server-debuginfo~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-sdk", rpm:"x86_64/xorg-x11-server-sdk~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xvfb", rpm:"x86_64/xorg-x11-server-Xvfb~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xorg-x11-server-Xnest", rpm:"x86_64/xorg-x11-server-Xnest~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xvfb", rpm:"i386/xorg-x11-server-Xvfb~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xorg", rpm:"i386/xorg-x11-server-Xorg~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-sdk", rpm:"i386/xorg-x11-server-sdk~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/xorg-x11-server-debuginfo", rpm:"i386/debug/xorg-x11-server-debuginfo~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xdmx", rpm:"i386/xorg-x11-server-Xdmx~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xorg-x11-server-Xnest", rpm:"i386/xorg-x11-server-Xnest~1.0.1~9.fc5.6", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
