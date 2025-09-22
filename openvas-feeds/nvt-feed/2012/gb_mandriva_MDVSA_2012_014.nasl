# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2012-02/msg00004.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831540");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-13 16:32:55 +0530 (Mon, 13 Feb 2012)");
  script_cve_id("CVE-2011-2720");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"MDVSA", value:"2012:014");
  script_name("Mandriva Update for glpi MDVSA-2012:014 (glpi)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glpi'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"glpi on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in GLPI:

  The autocompletion functionality in GLPI before 0.80.2 does not
  blacklist certain username and password fields, which allows remote
  attackers to obtain sensitive information via a crafted POST request
  (CVE-2011-2720).

  This advisory provides the latest version of GLPI (0.80.6) which are
  not vulnerable to this issue. Additionally the latest versions of
  the corresponding plugins are also being provided.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"glpi", rpm:"glpi~0.80.6~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-archires", rpm:"glpi-plugin-archires~1.9.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-datainjection", rpm:"glpi-plugin-datainjection~2.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-fusioninventory", rpm:"glpi-plugin-fusioninventory~2.4.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-fusioninventory-deploy", rpm:"glpi-plugin-fusioninventory-deploy~2.4.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-fusioninventory-inventory", rpm:"glpi-plugin-fusioninventory-inventory~2.4.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-fusioninventory-snmp", rpm:"glpi-plugin-fusioninventory-snmp~2.4.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-genericobject", rpm:"glpi-plugin-genericobject~2.0.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-manufacturersimports", rpm:"glpi-plugin-manufacturersimports~1.4.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-massocsimport", rpm:"glpi-plugin-massocsimport~1.5.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-racks", rpm:"glpi-plugin-racks~1.2.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-reports", rpm:"glpi-plugin-reports~1.5.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glpi-plugin-webservices", rpm:"glpi-plugin-webservices~1.2.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Parallel-ForkManager", rpm:"perl-Parallel-ForkManager~0.7.9~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
