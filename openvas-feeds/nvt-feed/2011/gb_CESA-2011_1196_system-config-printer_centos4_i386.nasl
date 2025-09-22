# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017704.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880968");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:1196");
  script_cve_id("CVE-2011-2899");
  script_name("CentOS Update for system-config-printer CESA-2011:1196 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'system-config-printer'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"system-config-printer on CentOS 4");
  script_tag(name:"insight", value:"system-config-printer is a print queue configuration tool with a graphical
  user interface.

  It was found that system-config-printer did not properly sanitize NetBIOS
  and workgroup names when searching for network printers. A remote attacker
  could use this flaw to execute arbitrary code with the privileges of the
  user running system-config-printer. (CVE-2011-2899)

  All users of system-config-printer are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. Running
  instances of system-config-printer must be restarted for this update to
  take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"system-config-printer", rpm:"system-config-printer~0.6.116.10~1.6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"system-config-printer-gui", rpm:"system-config-printer-gui~0.6.116.10~1.6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
