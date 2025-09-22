# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019339.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881639");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:11 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2011-2722", "CVE-2013-0200");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"CESA", value:"2013:0500");
  script_name("CentOS Update for hpijs CESA-2013:0500 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hpijs'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"hpijs on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The hplip packages contain the Hewlett-Packard Linux Imaging and Printing
  Project (HPLIP), which provides drivers for Hewlett-Packard printers and
  multi-function peripherals.

  Several temporary file handling flaws were found in HPLIP. A local attacker
  could use these flaws to perform a symbolic link attack, overwriting
  arbitrary files accessible to a process using HPLIP. (CVE-2013-0200,
  CVE-2011-2722)

  The CVE-2013-0200 issues were discovered by Tim Waugh of Red Hat.

  The hplip packages have been upgraded to upstream version 3.12.4, which
  provides a number of bug fixes and enhancements over the previous version.
  (BZ#731900)

  This update also fixes the following bugs:

  * Previously, the hpijs package required the obsolete cupsddk-drivers
  package, which was provided by the cups package. Under certain
  circumstances, this dependency caused hpijs installation to fail. This
  bug has been fixed and hpijs no longer requires cupsddk-drivers.
  (BZ#829453)

  * The configuration of the Scanner Access Now Easy (SANE) back end is
  located in the /etc/sane.d/dll.d/ directory, however, the hp-check
  utility checked only the /etc/sane.d/dll.conf file. Consequently,
  hp-check checked for correct installation, but incorrectly reported a
  problem with the way the SANE back end was installed. With this update,
  hp-check properly checks for installation problems in both locations as
  expected. (BZ#683007)

  All users of hplip are advised to upgrade to these updated packages, which
  fix these issues and add these enhancements.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~3.12.4~4.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.4~4.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-common", rpm:"hplip-common~3.12.4~4.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.4~4.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-libs", rpm:"hplip-libs~3.12.4~4.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsane-hpaio", rpm:"libsane-hpaio~3.12.4~4.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
