# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-August/msg00007.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870465");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:1154-01");
  script_cve_id("CVE-2011-2895");
  script_name("RedHat Update for libXfont RHSA-2011:1154-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"libXfont on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The libXfont packages provide the X.Org libXfont runtime library. X.Org is
  an open source implementation of the X Window System.

  A buffer overflow flaw was found in the way the libXfont library, used by
  the X.Org server, handled malformed font files compressed using UNIX
  compress. A malicious, local user could exploit this issue to potentially
  execute arbitrary code with the privileges of the X.Org server.
  (CVE-2011-2895)

  Users of libXfont should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. All running X.Org server instances
  must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.2.2~1.0.4.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.2.2~1.0.4.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.2.2~1.0.4.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
