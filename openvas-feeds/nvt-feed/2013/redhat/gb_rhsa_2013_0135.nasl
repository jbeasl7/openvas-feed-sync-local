# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870883");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:28 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-2370");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2013:0135-01");
  script_name("RedHat Update for gtk2 RHSA-2013:0135-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"gtk2 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"GIMP Toolkit (GTK+) is a multi-platform toolkit for creating graphical user
  interfaces.

  An integer overflow flaw was found in the X BitMap (XBM) image file loader
  in GTK+. A remote attacker could provide a specially-crafted XBM image file
  that, when opened in an application linked against GTK+ (such as Nautilus),
  would cause the application to crash. (CVE-2012-2370)

  This update also fixes the following bugs:

  * Due to a bug in the Input Method GTK+ module, the usage of the Taiwanese
  Big5 (zh_TW.Big-5) locale led to the unexpected termination of certain
  applications, such as the GDM greeter. The bug has been fixed, and the
  Taiwanese locale no longer causes applications to terminate unexpectedly.
  (BZ#487630)

  * When a file was initially selected after the GTK+ file chooser dialog was
  opened and the Location field was visible, pressing the Enter key did not
  open the file. With this update, the initially selected file is opened
  regardless of the visibility of the Location field. (BZ#518483)

  * When a file was initially selected after the GTK+ file chooser dialog was
  opened and the Location field was visible, pressing the Enter key did not
  change into the directory. With this update, the dialog changes into the
  initially selected directory regardless of the visibility of the Location
  field. (BZ#523657)

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"gtk2", rpm:"gtk2~2.10.4~29.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gtk2-debuginfo", rpm:"gtk2-debuginfo~2.10.4~29.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gtk2-devel", rpm:"gtk2-devel~2.10.4~29.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
