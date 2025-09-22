# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883017");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-6133");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-03-09 04:08:04 +0100 (Sat, 09 Mar 2019)");
  script_name("CentOS Update for polkit CESA-2019:0230 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0230");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-March/023215.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit'
  package(s) announced via the CESA-2019:0230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The polkit packages provide a component for controlling system-wide
privileges. This component provides a uniform and organized way for
non-privileged processes to communicate with privileged ones.

Security Fix(es):

  * polkit: Temporary auth hijacking via PID reuse and non-atomic fork
(CVE-2019-6133)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Jan Rybar (freedesktop.org) for reporting this
issue. Upstream acknowledges Jann Horn (Google Project Zero) as the
original reporter.");

  script_tag(name:"affected", value:"polkit on CentOS 7.");

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

  if ((res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.112~18.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-devel", rpm:"polkit-devel~0.112~18.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-docs", rpm:"polkit-docs~0.112~18.el7_6.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
