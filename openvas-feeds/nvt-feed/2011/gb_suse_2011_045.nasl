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
  script_oid("1.3.6.1.4.1.25623.1.0.850172");
  script_version("2021-05-19T13:10:04+0000");
  script_tag(name:"last_modification", value:"2021-05-19 13:10:04 +0000 (Wed, 19 May 2021)");
  script_tag(name:"creation_date", value:"2011-12-05 12:16:08 +0530 (Mon, 05 Dec 2011)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 15:53:00 +0000 (Fri, 31 Jan 2020)");
  script_xref(name:"SUSE-SA", value:"2011-045");
  script_cve_id("CVE-2006-7246");
  script_name("SUSE: Security Advisory for NetworkManager, wpa_supplicant, NetworkManager-gnome (SUSE-SA:2011:045)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager, wpa_supplicant, NetworkManager-gnome'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE11\.3)");

  script_tag(name:"impact", value:"man in the middle");

  script_tag(name:"affected", value:"NetworkManager, wpa_supplicant, NetworkManager-gnome on openSUSE 11.3, openSUSE 11.4");

  script_tag(name:"insight", value:"When 802.11X authentication is used (ie WPA Enterprise)
  NetworkManager did not pin a certificate's subject to an ESSID. A
  rogue access point could therefore be used to conduct MITM attacks
  by using any other valid certificate issued by the same CA as used
  in the original network CVE-2006-7246. If password based
  authentication is used (e.g. via PEAP or EAP-TTLS) this means an
  attacker could sniff and potentially crack the password hashes of
  the victims.

  The certificate checks are only performed on newly created
  connections. Users must therefore delete and re-create any existing
  WPA Enterprise connections using e.g. nm-connection-editor to take
  advantage of the checks.

  knetworkmanager is also affected by but a fix is currently not
  available. Users of knetworkmanager are advised to use nm-applet for
  802.11X networks instead.

  The following document gives a more detailed explanation about the
  problem in general. Administrators are advised to take the
  opportunity to review security of their wireless networks if 802.11X
  authentication is used.");

  script_xref(name:"URL", value:"http://www.suse.de/~lnussel/The_Evil_Twin_problem_with_WPA2-Enterprise_v1.1.pdf");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

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

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.8.2~15.28.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.8.2~15.28.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-doc", rpm:"NetworkManager-doc~0.8.2~15.28.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.8.2~15.28.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.8.2~9.12.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.7.3~3.4.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~0.7.3~3.4.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE11.3") {
  if(!isnull(res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.8~8.13.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.8~8.13.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-doc", rpm:"NetworkManager-doc~0.8~8.13.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.8~8.13.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.8~6.3.2", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.7.1~5.3.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~0.7.1~5.3.1", rls:"openSUSE11.3"))) {
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
