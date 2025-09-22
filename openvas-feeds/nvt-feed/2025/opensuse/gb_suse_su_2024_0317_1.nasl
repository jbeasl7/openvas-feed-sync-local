# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0317.1");
  script_cve_id("CVE-2018-20319", "CVE-2020-12105", "CVE-2020-12823");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 16:22:17 +0000 (Thu, 14 May 2020)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0317-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0317-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240317-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215669");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017849.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openconnect' package(s) announced via the SUSE-SU-2024:0317-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openconnect fixes the following issues:

- Update to release 9.12:

 * Explicitly reject overly long tun device names.
 * Increase maximum input size from stdin (#579).
 * Ignore 0.0.0.0 as NBNS address (!446, vpnc-scripts#58).
 * Fix stray (null) in URL path after Pulse authentication (4023bd95).
 * Fix config XML parsing mistake that left GlobalProtect ESP non-working in v9.10 (!475).
 * Fix case sensitivity in GPST header matching (!474).

- Update to release 9.10:

 * Fix external browser authentication with KDE plasma-nm < 5.26.
 * Always redirect stdout to stderr when spawning external browser.
 * Increase default queue length to 32 packets.
 * Fix receiving multiple packets in one TLS frame, and single packets split across multiple TLS frames, for Array.
 * Handle idiosyncratic variation in search domain separators for all protocols
 * Support region selection field for Pulse authentication
 * Support modified configuration packet from Pulse 9.1R16 servers
 * Allow hidden form fields to be populated or converted to text fields on the command line
 * Support yet another strange way of encoding challenge-based 2FA for GlobalProtect
 * Add --sni option (and corresponding C and Java API functions) to allow domain-fronting connections in censored/filtered network environments
 * Parrot a GlobalProtect server's software version, if present, as the client version (!333)
 * Fix NULL pointer dereference that has left Android builds broken since v8.20 (!389).
 * Fix Fortinet authentication bug where repeated SVPNCOOKIE causes segfaults (#514, !418).
 * Support F5 VPNs which encode authentication forms only in JSON, not in HTML.
 * Support simultaneous IPv6 and Legacy IP ('dual-stack') for Fortinet .
 * Support 'FTM-push' token mode for Fortinet VPNs .
 * Send IPv6-compatible version string in Pulse IF/T session establishment
 * Add --no-external-auth option to not advertise external-browser authentication
 * Many small improvements in server response parsing, and better logging messages and documentation.

- Update to release 9.01:

 * Add support for AnyConnect 'Session Token Re-use Anchor Protocol' (STRAP)
 * Add support for AnyConnect 'external browser' SSO mode
 * Bugfix RSA SecurID token decryption and PIN entry forms, broken in v8.20
 * Support Cisco's multiple-certificate authentication
 * Revert GlobalProtect default route handling change from v8.20
 * Suppo split-exclude routes for Fortinet
 * Add webview callback and SAML/SSO support for AnyConnect, GlobalProtect

- Update to release 8.20:

 * Support non-AEAD ciphersuites in DTLSv1.2 with AnyConnect.
 * Emulated a newer version of GlobalProtect official clients,
 5.1.5-8, was 4.0.2-19
 * Support Juniper login forms containing both password and 2FA
 token
 * Explicitly disable 3DES and RC4, unless enabled with
 --allow-insecure-crypto
 * Allow protocols to delay tunnel setup and shutdown (!117)
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openconnect' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"liboath-devel", rpm:"liboath-devel~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath0", rpm:"liboath0~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenconnect5", rpm:"libopenconnect5~9.12~150400.15.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpskc-devel", rpm:"libpskc-devel~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpskc0", rpm:"libpskc0~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstoken1", rpm:"libstoken1~0.81~150400.13.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit", rpm:"oath-toolkit~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit-xml", rpm:"oath-toolkit-xml~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openconnect", rpm:"openconnect~9.12~150400.15.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openconnect-devel", rpm:"openconnect-devel~9.12~150400.15.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openconnect-doc", rpm:"openconnect-doc~9.12~150400.15.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openconnect-lang", rpm:"openconnect-lang~9.12~150400.15.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_oath", rpm:"pam_oath~2.6.2~150000.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stoken", rpm:"stoken~0.81~150400.13.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stoken-devel", rpm:"stoken-devel~0.81~150400.13.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stoken-gui", rpm:"stoken-gui~0.81~150400.13.2.1", rls:"openSUSELeap15.5"))) {
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
