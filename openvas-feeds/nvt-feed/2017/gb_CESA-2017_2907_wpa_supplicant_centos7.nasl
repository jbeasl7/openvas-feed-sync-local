# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882787");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-18 16:53:28 +0200 (Wed, 18 Oct 2017)");
  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13080", "CVE-2017-13082",
                "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for wpa_supplicant CESA-2017:2907 centos7");
  script_tag(name:"summary", value:"Check the version of wpa_supplicant");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The wpa_supplicant packages contain an
802.1X Supplicant with support for WEP, WPA, WPA2 (IEEE 802.11i / RSN), and
various EAP authentication methods. They implement key negotiation with a WPA
Authenticator for client stations and controls the roaming and IEEE 802.11
authentication and association of the WLAN driver.

Security Fix(es):

  * A new exploitation technique called key reinstallation attacks (KRACK)
affecting WPA2 has been discovered. A remote attacker within Wi-Fi range
could exploit these attacks to decrypt Wi-Fi traffic or possibly inject
forged Wi-Fi packets by manipulating cryptographic handshakes used by the
WPA2 protocol. (CVE-2017-13077, CVE-2017-13078, CVE-2017-13080,
CVE-2017-13082, CVE-2017-13086, CVE-2017-13087, CVE-2017-13088)

Red Hat would like to thank CERT for reporting these issues. Upstream
acknowledges Mathy Vanhoef (University of Leuven) as the original reporter
of these issues.");
  script_tag(name:"affected", value:"wpa_supplicant on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:2907");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-October/022569.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.6~5.el7_4.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
