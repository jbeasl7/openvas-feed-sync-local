# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3380.1");
  script_cve_id("CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-8041", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088", "CVE-2018-14526", "CVE-2019-11555", "CVE-2019-13377", "CVE-2019-16275", "CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-18 17:01:41 +0000 (Thu, 18 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3380-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203380-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930079");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007800.html");
  script_xref(name:"URL", value:"https://w1.fi/security/2017-1/");
  script_xref(name:"URL", value:"https://w1.fi/security/2018-1/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-1/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-2/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-4/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-5/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-6/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the SUSE-SU-2020:3380-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wpa_supplicant fixes the following issues:

Security issue fixed:

- CVE-2019-16275: Fixed an AP mode PMF disconnection protection bypass (bsc#1150934).

Non-security issues fixed:

- Enable SAE support (jsc#SLE-14992).
- Limit P2P_DEVICE name to appropriate ifname size.
- Fix wicked wlan (bsc#1156920)
- Restore fi.epitest.hostap.WPASupplicant.service (bsc#1167331)
- With v2.9 fi.epitest.hostap.WPASupplicant.service is obsolete (bsc#1167331)
- Fix WLAN config on boot with wicked. (bsc#1166933)
- Update to 2.9 release:
 * SAE changes
 - disable use of groups using Brainpool curves
 - improved protection against side channel attacks
 [[link moved to references]]
 * EAP-pwd changes
 - disable use of groups using Brainpool curves
 - allow the set of groups to be configured (eap_pwd_groups)
 - improved protection against side channel attacks
 [[link moved to references]]
 * fixed FT-EAP initial mobility domain association using PMKSA caching
 (disabled by default for backwards compatibility, can be enabled
 with ft_eap_pmksa_caching=1)
 * fixed a regression in OpenSSL 1.1+ engine loading
 * added validation of RSNE in (Re)Association Response frames
 * fixed DPP bootstrapping URI parser of channel list
 * extended EAP-SIM/AKA fast re-authentication to allow use with FILS
 * extended ca_cert_blob to support PEM format
 * improved robustness of P2P Action frame scheduling
 * added support for EAP-SIM/AKA using anonymous@realm identity
 * fixed Hotspot 2.0 credential selection based on roaming consortium
 to ignore credentials without a specific EAP method
 * added experimental support for EAP-TEAP peer (RFC 7170)
 * added experimental support for EAP-TLS peer with TLS v1.3
 * fixed a regression in WMM parameter configuration for a TDLS peer
 * fixed a regression in operation with drivers that offload 802.1X
 4-way handshake
 * fixed an ECDH operation corner case with OpenSSL
 * SAE changes
 - added support for SAE Password Identifier
 - changed default configuration to enable only groups 19, 20, 21
 (i.e., disable groups 25 and 26) and disable all unsuitable groups
 completely based on REVmd changes
 - do not regenerate PWE unnecessarily when the AP uses the
 anti-clogging token mechanisms
 - fixed some association cases where both SAE and FT-SAE were enabled
 on both the station and the selected AP
 - started to prefer FT-SAE over SAE AKM if both are enabled
 - started to prefer FT-SAE over FT-PSK if both are enabled
 - fixed FT-SAE when SAE PMKSA caching is used
 - reject use of unsuitable groups based on new implementation guidance
 in REVmd (allow only FFC groups with prime >= 3072 bits and ECC
 groups with prime >= 256)
 - minimize timing and memory use differences in PWE derivation
 [[link moved to references]] (CVE-2019-9494, bsc#1131868)
 * EAP-pwd changes
 - minimize timing and memory use differences in PWE derivation
 [[link moved to references]] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.9~4.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~2.9~4.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debugsource", rpm:"wpa_supplicant-debugsource~2.9~4.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.9~4.20.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~2.9~4.20.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debugsource", rpm:"wpa_supplicant-debugsource~2.9~4.20.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.9~4.20.1", rls:"SLES15.0"))) {
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
