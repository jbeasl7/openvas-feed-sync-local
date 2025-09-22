# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833774");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-28488");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 20:01:26 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:21:38 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for connman (openSUSE-SU-2023:0369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0369-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JE33AUDBYZOO3LHUWP2WCZRW7H3IHMC5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'connman'
  package(s) announced via the openSUSE-SU-2023:0369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for connman fixes the following issues:

     Update to 1.42

  * Fix issue with iwd and signal strength calculation.

  * Fix issue with iwd and handling service removal.

  * Fix issue with iwd and handling new connections.

  * Fix issue with handling default online check URL.

  * Fix issue with handling nameservers refresh.

  * Fix issue with handling proxy from DHCP lease. (boo#1210395
         CVE-2023-28488)

  * Fix issue with handling multiple proxies from PAC.

  * Fix issue with handling manual time update changes.

  * Fix issue with handling invalid gateway routes.

  * Fix issue with handling hidden WiFi agent requests.

  * Fix issue with handling WiFi SAE authentication failure.

  * Fix issue with handling DNS Proxy and TCP server replies.

  * Add support for regulatory domain following timezone.

  * Add support for localtime configuration option.");

  script_tag(name:"affected", value:"'connman' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"connman", rpm:"connman~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-client", rpm:"connman-client~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-devel", rpm:"connman-devel~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-doc", rpm:"connman-doc~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-nmcompat", rpm:"connman-nmcompat~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-iospm", rpm:"connman-plugin-iospm~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-l2tp", rpm:"connman-plugin-l2tp~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-openvpn", rpm:"connman-plugin-openvpn~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-polkit", rpm:"connman-plugin-polkit~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-pptp", rpm:"connman-plugin-pptp~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-wireguard", rpm:"connman-plugin-wireguard~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-test", rpm:"connman-test~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-vpnc", rpm:"connman-plugin-vpnc~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-hh2serial-gps", rpm:"connman-plugin-hh2serial-gps~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-tist", rpm:"connman-plugin-tist~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman", rpm:"connman~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-client", rpm:"connman-client~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-devel", rpm:"connman-devel~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-doc", rpm:"connman-doc~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-nmcompat", rpm:"connman-nmcompat~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-iospm", rpm:"connman-plugin-iospm~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-l2tp", rpm:"connman-plugin-l2tp~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-openvpn", rpm:"connman-plugin-openvpn~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-polkit", rpm:"connman-plugin-polkit~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-pptp", rpm:"connman-plugin-pptp~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-wireguard", rpm:"connman-plugin-wireguard~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-test", rpm:"connman-test~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-vpnc", rpm:"connman-plugin-vpnc~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-hh2serial-gps", rpm:"connman-plugin-hh2serial-gps~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"connman-plugin-tist", rpm:"connman-plugin-tist~1.42~bp155.4.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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