# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1293.1");
  script_cve_id("CVE-2023-42843", "CVE-2023-42950", "CVE-2023-42956", "CVE-2024-23252", "CVE-2024-23254", "CVE-2024-23263", "CVE-2024-23280", "CVE-2024-23284");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-08 22:48:38 +0000 (Mon, 08 Apr 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1293-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241293-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222010");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-April/018353.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2024:1293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"webkit2gtk3 was updated to fix the following issues:

Update to version 2.44.0 (boo#1222010):

- CVE-2024-23252:

 Credit to anbu1024 of SecANT.
 Impact: Processing web content may lead to a denial-of-service.
 Description: The issue was addressed with improved memory handling.

- CVE-2024-23254:

 Credit to James Lee (@Windowsrcer).
 Impact: A malicious website may exfiltrate audio data cross-origin.
 Description: The issue was addressed with improved UI handling.

- CVE-2024-23263:

 Credit to Johan Carlsson (joaxcar).
 Impact: Processing maliciously crafted web content may prevent
 Content Security Policy from being enforced. Description: A logic
 issue was addressed with improved validation.

- CVE-2024-23280:

 Credit to An anonymous researcher.
 Impact: A maliciously crafted webpage may be able to fingerprint the
 user. Description: An injection issue was addressed with improved
 validation.

- CVE-2024-23284:

 Credit to Georg Felber and Marco Squarcina.
 Impact: Processing maliciously crafted web content may prevent
 Content Security Policy from being enforced. Description: A logic
 issue was addressed with improved state management.

- CVE-2023-42950:

 Credit to Nan Wang (@eternalsakura13) of 360 Vulnerability Research
 Institute and rushikesh nandedkar.
 Impact: Processing maliciously crafted web content may lead to
 arbitrary code execution. Description: A use after free issue was
 addressed with improved memory management.

- CVE-2023-42956:

 Credit to SungKwon Lee (Demon.Team).
 Impact: Processing web content may lead to a denial-of-service.
 Description: The issue was addressed with improved memory handling.

- CVE-2023-42843:

 Credit to Kacper Kwapisz (@KKKas_).
 Impact: Visiting a malicious website may lead to address bar
 spoofing. Description: An inconsistent user interface issue was
 addressed with improved state management.


+ Make the DOM accessibility tree reachable from UI process with GTK4.
+ Removed the X11 and WPE renderers in favor of DMA-BUF.
+ Improved vblank synchronization when rendering.
+ Removed key event reinjection in GTK4 to make keyboard shortcuts work in web sites.
+ Fix gamepads detection by correctly handling focused window in GTK4.

- Use WebAssembly on aarch64. It is the upstream default and no
 longer makes the build fail. Stop passing -DENABLE_C_LOOP=ON,
 -DENABLE_WEBASSEMBLY=OFF and -DENABLE_SAMPLING_PROFILER=OFF for
 the same reason.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.44.0~4.3.2", rls:"SLES12.0SP5"))) {
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
