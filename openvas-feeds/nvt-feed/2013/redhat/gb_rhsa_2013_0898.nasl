# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871004");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-06-04 09:18:29 +0530 (Tue, 04 Jun 2013)");
  script_cve_id("CVE-2013-1993");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for mesa RHSA-2013:0898-01");

  script_xref(name:"RHSA", value:"2013:0898-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-June/msg00004.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mesa'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"mesa on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mesa provides a 3D graphics API that is compatible with Open Graphics
  Library (OpenGL). It also provides hardware-accelerated drivers for many
  popular graphics chips.

  It was found that Mesa did not correctly validate messages from the X
  server. A malicious X server could cause an application using Mesa to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2013-1993)

  All users of Mesa are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. All running
  applications linked against Mesa must be restarted for this update to take
  effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"glx-utils", rpm:"glx-utils~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-debuginfo", rpm:"mesa-debuginfo~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGL", rpm:"mesa-libGL~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGL-devel", rpm:"mesa-libGL-devel~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLU", rpm:"mesa-libGLU~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLU-devel", rpm:"mesa-libGLU-devel~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLw", rpm:"mesa-libGLw~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLw-devel", rpm:"mesa-libGLw-devel~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libOSMesa", rpm:"mesa-libOSMesa~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libOSMesa-devel", rpm:"mesa-libOSMesa-devel~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-source", rpm:"mesa-source~6.5.1~7.11.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
