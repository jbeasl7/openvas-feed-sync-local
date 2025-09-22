# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882765");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-13 07:16:22 +0200 (Wed, 13 Sep 2017)");
  script_cve_id("CVE-2017-1000250");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-17 02:29:00 +0000 (Sat, 17 Feb 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for bluez CESA-2017:2685 centos6");
  script_tag(name:"summary", value:"Check the version of bluez");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The bluez packages contain the following
utilities for use in Bluetooth applications: hcitool, hciattach, hciconfig,
bluetoothd, l2ping, start scripts (Red Hat), and pcmcia configuration files.

Security Fix(es):

  * An information-disclosure flaw was found in the bluetoothd implementation
of the Service Discovery Protocol (SDP). A specially crafted Bluetooth
device could, without prior pairing or user interaction, retrieve portions
of the bluetoothd process memory, including potentially sensitive
information such as Bluetooth encryption keys. (CVE-2017-1000250)

Red Hat would like to thank Armis Labs for reporting this issue.");
  script_tag(name:"affected", value:"bluez on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:2685");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-September/022531.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"bluez", rpm:"bluez~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-alsa", rpm:"bluez-alsa~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-compat", rpm:"bluez-compat~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-gstreamer", rpm:"bluez-gstreamer~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-libs", rpm:"bluez-libs~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-libs-devel", rpm:"bluez-libs-devel~4.66~2.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
