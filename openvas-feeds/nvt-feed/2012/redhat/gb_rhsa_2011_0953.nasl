# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870650");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:41:27 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-2520");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 02:53:00 +0000 (Sun, 21 Jan 2024)");
  script_xref(name:"RHSA", value:"2011:0953-01");
  script_name("RedHat Update for system-config-firewall RHSA-2011:0953-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'system-config-firewall'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"system-config-firewall on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"system-config-firewall is a graphical user interface for basic firewall
  setup.

  It was found that system-config-firewall used the Python pickle module in
  an insecure way when sending data (via D-Bus) to the privileged back-end
  mechanism. A local user authorized to configure firewall rules using
  system-config-firewall could use this flaw to execute arbitrary code with
  root privileges, by sending a specially-crafted serialized object.
  (CVE-2011-2520)

  Red Hat would like to thank Marco Slaviero of SensePost for reporting this
  issue.

  This erratum updates system-config-firewall to use JSON (JavaScript Object
  Notation) for data exchange, instead of pickle. Therefore, an updated
  version of system-config-printer that uses this new communication data
  format is also provided in this erratum.

  Users of system-config-firewall are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. Running
  instances of system-config-firewall must be restarted before the utility
  will be able to communicate with its updated back-end.");
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

  if ((res = isrpmvuln(pkg:"system-config-printer", rpm:"system-config-printer~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-debuginfo", rpm:"system-config-printer-debuginfo~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-libs", rpm:"system-config-printer-libs~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-udev", rpm:"system-config-printer-udev~1.1.16~17.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-firewall", rpm:"system-config-firewall~1.2.27~3.el6_1.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-firewall-base", rpm:"system-config-firewall-base~1.2.27~3.el6_1.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-firewall-tui", rpm:"system-config-firewall-tui~1.2.27~3.el6_1.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
