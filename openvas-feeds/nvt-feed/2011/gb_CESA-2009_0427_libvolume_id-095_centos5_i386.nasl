# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015797.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880822");
  script_version("2022-07-05T11:37:01+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:01 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:0427");
  script_cve_id("CVE-2009-1185");
  script_name("CentOS Update for libvolume_id-095 CESA-2009:0427 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvolume_id-095'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libvolume_id-095 on CentOS 5");
  script_tag(name:"insight", value:"udev provides a user-space API and implements a dynamic device directory,
  providing only the devices present on the system. udev replaces devfs in
  order to provide greater hot plug functionality. Netlink is a datagram
  oriented service, used to transfer information between kernel modules and
  user-space processes.

  It was discovered that udev did not properly check the origin of Netlink
  messages. A local attacker could use this flaw to gain root privileges via
  a crafted Netlink message sent to udev, causing it to create a
  world-writable block device file for an existing system block device (for
  example, the root file system). (CVE-2009-1185)

  Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
  responsibly reporting this flaw.

  Users of udev are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, the udevd daemon will be restarted automatically.");
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
report = "";

if(release == "CentOS5") {
  if(!isnull(res = isrpmvuln(pkg:"libvolume_id", rpm:"libvolume_id~095~14.20.el5_3", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvolume_id-devel", rpm:"libvolume_id-devel~095~14.20.el5_3", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~095~14.20.el5_3", rls:"CentOS5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
