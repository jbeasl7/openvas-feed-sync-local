# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871375");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-12 06:08:23 +0200 (Fri, 12 Jun 2015)");
  script_cve_id("CVE-2015-1863", "CVE-2015-4142");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for wpa_supplicant RHSA-2015:1090-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The wpa_supplicant package contains an 802.1X Supplicant with support for
WEP, WPA, WPA2 (IEEE 802.11i / RSN), and various EAP authentication
methods. It implements key negotiation with a WPA Authenticator for client
stations and controls the roaming and IEEE 802.11 authentication and
association of the WLAN driver.

A buffer overflow flaw was found in the way wpa_supplicant handled SSID
information in the Wi-Fi Direct / P2P management frames. A specially
crafted frame could allow an attacker within Wi-Fi radio range to cause
wpa_supplicant to crash or, possibly, execute arbitrary code.
(CVE-2015-1863)

An integer underflow flaw, leading to a buffer over-read, was found in the
way wpa_supplicant handled WMM Action frames. A specially crafted frame
could possibly allow an attacker within Wi-Fi radio range to cause
wpa_supplicant to crash. (CVE-2015-4142)

Red Hat would like to thank Jouni Malinen of the wpa_supplicant upstream
for reporting the CVE-2015-1863 issue. Upstream acknowledges Alibaba
security team as the original reporter.

This update also adds the following enhancement:

  * Prior to this update, wpa_supplicant did not provide a way to require the
host name to be listed in an X.509 certificate's Common Name or Subject
Alternative Name, and only allowed host name suffix or subject substring
checks. This update introduces a new configuration directive,
'domain_match', which adds a full host name check. (BZ#1178263)

All wpa_supplicant users are advised to upgrade to this updated package,
which contains backported patches to correct these issues and add this
enhancement. After installing this update, the wpa_supplicant service will
be restarted automatically.");
  script_tag(name:"affected", value:"wpa_supplicant on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1090-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-June/msg00017.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.0~17.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~2.0~17.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}