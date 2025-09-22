# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-November/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870862");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-11-15 11:41:24 +0530 (Thu, 15 Nov 2012)");
  script_cve_id("CVE-2012-4505");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:1461-01");
  script_name("RedHat Update for libproxy RHSA-2012:1461-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libproxy'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"libproxy on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"libproxy is a library that handles all the details of proxy configuration.

  A buffer overflow flaw was found in the way libproxy handled the
  downloading of proxy auto-configuration (PAC) files. A malicious server
  hosting a PAC file or a man-in-the-middle attacker could use this flaw to
  cause an application using libproxy to crash or, possibly, execute
  arbitrary code, if the proxy settings obtained by libproxy (from the
  environment or the desktop environment settings) instructed the use of a
  PAC proxy configuration. (CVE-2012-4505)

  This issue was discovered by the Red Hat Security Response Team.

  Users of libproxy should upgrade to these updated packages, which contain
  a backported patch to correct this issue. All applications using libproxy
  must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libproxy", rpm:"libproxy~0.3.0~3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-bin", rpm:"libproxy-bin~0.3.0~3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-debuginfo", rpm:"libproxy-debuginfo~0.3.0~3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-python", rpm:"libproxy-python~0.3.0~3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
