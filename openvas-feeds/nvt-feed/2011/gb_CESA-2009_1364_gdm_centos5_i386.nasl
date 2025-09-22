# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016157.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880844");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:1364");
  script_cve_id("CVE-2009-2697");
  script_name("CentOS Update for gdm CESA-2009:1364 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gdm on CentOS 5");
  script_tag(name:"insight", value:"The GNOME Display Manager (GDM) is a configurable re-implementation of XDM,
  the X Display Manager. GDM allows you to log in to your system with the X
  Window System running, and supports running several different X sessions on
  your local machine at the same time.

  A flaw was found in the way the gdm package was built. The gdm package was
  missing TCP wrappers support, which could result in an administrator
  believing they had access restrictions enabled when they did not.
  (CVE-2009-2697)

  This update also fixes the following bugs:

  * the GDM Reference Manual is now included with the gdm packages. The
  gdm-docs package installs this document in HTML format in
  '/usr/share/doc/'. (BZ#196054)

  * GDM appeared in English on systems using Telugu (te_IN). With this
  update, GDM has been localized in te_IN. (BZ#226931)

  * the Ctrl+Alt+Backspace sequence resets the X server when in runlevel 5.
  In previous releases, however, repeated use of this sequence prevented GDM
  from starting the X server as part of the reset process. This was because
  GDM sometimes did not notice the X server shutdown properly and would
  subsequently fail to complete the reset process. This update contains an
  added check to explicitly notify GDM whenever the X server is terminated,
  ensuring that resets are executed reliably. (BZ#441971)

  * the 'gdm' user is now part of the 'audio' group by default. This enables
  audio support at the login screen. (BZ#458331)

  * the gui/modules/dwellmouselistener.c source code contained incorrect
  XInput code that prevented tablet devices from working properly. This
  update removes the errant code, ensuring that tablet devices work as
  expected. (BZ#473262)

  * a bug in the XOpenDevice() function prevented the X server from starting
  whenever a device defined in '/etc/X11/xorg.conf' was not actually plugged
  in. This update wraps XOpenDevice() in the gdk_error_trap_pop() and
  gdk_error_trap_push() functions, which resolves this bug. This ensures that
  the X server can start properly even when devices defined in
  '/etc/X11/xorg.conf' are not plugged in. (BZ#474588)

  All users should upgrade to these updated packages, which resolve these
  issues. GDM must be restarted for this update to take effect. Rebooting
  achieves this, but changing the runlevel from 5 to 3 and back to 5 also
  restarts GDM.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.16.0~56.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-docs", rpm:"gdm-docs~2.16.0~56.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
