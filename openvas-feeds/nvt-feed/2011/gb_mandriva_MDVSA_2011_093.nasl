# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-05/msg00017.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831402");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-23 16:55:31 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:N");
  script_xref(name:"MDVSA", value:"2011:093");
  script_cve_id("CVE-2010-0285");
  script_name("Mandriva Update for gnome-screensaver MDVSA-2011:093 (gnome-screensaver)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-screensaver'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"gnome-screensaver on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in gnome-screensaver:

  gnome-screensaver 2.14.3, 2.22.2, 2.27.x, 2.28.0, and 2.28.3, when the
  X configuration enables the extend screen option, allows physically
  proximate attackers to bypass screen locking, access an unattended
  workstation, and view half of the GNOME desktop by attaching an
  external monitor (CVE-2010-0285).

  The updated packages have been patched to correct this issue.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
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

  if ((res = isrpmvuln(pkg:"gnome-screensaver", rpm:"gnome-screensaver~2.24.0~1.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
