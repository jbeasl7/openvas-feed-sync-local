# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122782");
  script_cve_id("CVE-2015-0272", "CVE-2015-2924");
  script_tag(name:"creation_date", value:"2015-11-25 11:18:49 +0000 (Wed, 25 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2315");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2315.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ModemManager, NetworkManager, NetworkManager-libreswan, network-manager-applet' package(s) announced via the ELSA-2015-2315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ModemManager
[1.1.0-8.git20130913]
- rfcomm: don't open the ttys until NetworkManager connects them (rh #1251954)

[1.1.0-7.git20130913]
- iface-modem: fix MODEM_STATE_IS_INTERMEDIATE macro (rh #1200958)

NetworkManager
[1.0.6-27.0.1]
- fix build error on i386

[1:1.0.6-27]
* build: update vala-tools build requirement (rh #1274000)

[1:1.0.6-26]
- wifi: emit NEW_BSS on ScanDone to update APs in Wi-Fi device (rh #1267327)

[1:1.0.6-25]
- vpn: cancel the secrets request on agent timeout (rh #1272023)
- vpn: cancel the connect timer when vpn reconnects (rh #1272023)

[1:1.0.6-24]
- device: fix problem in not managing software devices (rh #1273879)

[1:1.0.6-23]
- wake-on-lan: ignore by default existing settings (rh #1270194)

[1:1.0.6-22]
- platform: fix detection of s390 CTC device (rh #1272974)
- core: fix queuing activation while waiting for carrier (rh #1079353)

[1:1.0.6-21]
- core: fix invalid assertion in nm_clear_g_signal_handler() (rh #1183444)

[1:1.0.6-20]
- rebuild package

[1:1.0.6-19]
- device: fix race wrongly managing external-down device (2) (rh #1269199)

[1:1.0.6-18]
- device/vlan: update VLAN MAC address when parent's one changes

[1:1.0.6-17]
- dhcp6: destroy the lease when destroying a client (rh #1260727)
- device: fix race wrongly managing external-down device (rh #1269199)

[1:1.0.6-16]
- device: silence spurious errors about activation schedule (rh #1269520)

[1:1.0.6-15]
- core: really fix enslaving team device to bridge (rh #1183444)

[1:1.0.6-14]
- platform: updating link cache when moving link to other netns (rh #1264361)
- nmtui: fix possible crash during secret request (rh #1267672)
- vpn: increase the plugin inactivity quit timer (rh #1268030)
- core: fix enslaving team device to bridge (rh #1183444)

[1:1.0.6-13]
- vpn-connection: set the MTU for the VPN IP interface (rh #1267004)
- modem-broadband: update modem's supported-ip-families (rh #1263959)
- wifi: fix a crash in on_bss_proxy_acquired() (rh #1267462)

[1:1.0.6-12]
- core: increase IPv6LL DAD timeout to 15 seconds (rh #1101809)

[1:1.0.6-11]
- platform: better handle devices without permanent address (rh #1264024)

[1:1.0.6-10]
- dhcp: fix crash in internal DHCP client (rh #1260727)

[1:1.0.6-9]
- build: fix installing language files (rh #1265117)

[1:1.0.6-8]
- nmcli: allow creating ADSL connections with 'nmcli connection add' (rh #1264089)

[1:1.0.6-7]
- ifcfg-rh: ignore GATEWAY from network file for DHCP connections (rh #1262972)

[1:1.0.6-6]
- device: retry DHCP after timeout/expiration for assumed connections (rh #1246496)
- device: retry creation of default connection after link is initialized (rh #1254089)

[1:1.0.6-5]
- config: add code comments to NetworkManager.conf file
- iface-helper: enabled slaac/dhcp4 based on connection setting only (rh #1260243)
- utils: avoid generation of duplicated assumed connection for veth devices (rh #1256430)
- nmcli: improve handling of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ModemManager, NetworkManager, NetworkManager-libreswan, network-manager-applet' package(s) on Oracle Linux 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"ModemManager", rpm:"ModemManager~1.1.0~8.git20130913.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ModemManager-devel", rpm:"ModemManager-devel~1.1.0~8.git20130913.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ModemManager-glib", rpm:"ModemManager-glib~1.1.0~8.git20130913.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ModemManager-glib-devel", rpm:"ModemManager-glib-devel~1.1.0~8.git20130913.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ModemManager-vala", rpm:"ModemManager-vala~1.1.0~8.git20130913.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-config-routing-rules", rpm:"NetworkManager-config-routing-rules~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-glib-devel", rpm:"NetworkManager-glib-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm-devel", rpm:"NetworkManager-libnm-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libreswan", rpm:"NetworkManager-libreswan~1.0.6~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libreswan-gnome", rpm:"NetworkManager-libreswan-gnome~1.0.6~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.0.6~27.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-gtk", rpm:"libnm-gtk~1.0.6~2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-gtk-devel", rpm:"libnm-gtk-devel~1.0.6~2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"network-manager-applet", rpm:"network-manager-applet~1.0.6~2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nm-connection-editor", rpm:"nm-connection-editor~1.0.6~2.el7", rls:"OracleLinux7"))) {
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
