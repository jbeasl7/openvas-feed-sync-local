# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.618899995198101");
  script_cve_id("CVE-2026-3909", "CVE-2026-3910", "CVE-2026-3913", "CVE-2026-3914", "CVE-2026-3915", "CVE-2026-3916", "CVE-2026-3917", "CVE-2026-3918", "CVE-2026-3919", "CVE-2026-3920", "CVE-2026-3921", "CVE-2026-3922", "CVE-2026-3923", "CVE-2026-3924", "CVE-2026-3925", "CVE-2026-3926", "CVE-2026-3927", "CVE-2026-3928", "CVE-2026-3929", "CVE-2026-3930", "CVE-2026-3931", "CVE-2026-3932", "CVE-2026-3934", "CVE-2026-3935", "CVE-2026-3936", "CVE-2026-3937", "CVE-2026-3938", "CVE-2026-3939", "CVE-2026-3940", "CVE-2026-3941", "CVE-2026-3942", "CVE-2026-4439", "CVE-2026-4440", "CVE-2026-4441", "CVE-2026-4442", "CVE-2026-4443", "CVE-2026-4444", "CVE-2026-4445", "CVE-2026-4446", "CVE-2026-4447", "CVE-2026-4448", "CVE-2026-4449", "CVE-2026-4450", "CVE-2026-4451", "CVE-2026-4452", "CVE-2026-4453", "CVE-2026-4454", "CVE-2026-4455", "CVE-2026-4456", "CVE-2026-4457", "CVE-2026-4458", "CVE-2026-4459", "CVE-2026-4460", "CVE-2026-4461", "CVE-2026-4462", "CVE-2026-4463", "CVE-2026-4464", "CVE-2026-4673", "CVE-2026-4674", "CVE-2026-4675", "CVE-2026-4676", "CVE-2026-4677", "CVE-2026-4678", "CVE-2026-4679", "CVE-2026-4680");
  script_tag(name:"creation_date", value:"2026-04-09 04:50:45 +0000 (Thu, 09 Apr 2026)");
  script_version("2026-04-09T06:11:03+0000");
  script_tag(name:"last_modification", value:"2026-04-09 06:11:03 +0000 (Thu, 09 Apr 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-20 15:16:18 +0000 (Fri, 20 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-6188cc51be)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-6188cc51be");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-6188cc51be");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2451647");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2026-6188cc51be advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to cef-146.0.9+g3ca6a87 + chromium 146.0.7680.164

* High CVE-2026-4673: Heap buffer overflow in WebAudio
* High CVE-2026-4674: Out of bounds read in CSS
* High CVE-2026-4675: Heap buffer overflow in WebGL
* High CVE-2026-4676: Use after free in Dawn
* High CVE-2026-4677: Out of bounds read in WebAudio
* High CVE-2026-4678: Use after free in WebGPU
* High CVE-2026-4679: Integer overflow in Fonts
* High CVE-2026-4680: Use after free in FedCM
* CVE-2026-4439: Out of bounds memory access in WebGL
* CVE-2026-4440: Out of bounds read and write in WebGL
* CVE-2026-4441: Use after free in Base
* CVE-2026-4442: Heap buffer overflow in CSS
* CVE-2026-4443: Heap buffer overflow in WebAudio
* CVE-2026-4444: Stack buffer overflow in WebRTC
* CVE-2026-4445: Use after free in WebRTC
* CVE-2026-4446: Use after free in WebRTC
* CVE-2026-4447: Inappropriate implementation in V8
* CVE-2026-4448: Heap buffer overflow in ANGLE
* CVE-2026-4449: Use after free in Blink
* CVE-2026-4450: Out of bounds write in V8
* CVE-2026-4451: Insufficient validation of untrusted input in Navigation
* CVE-2026-4452: Integer overflow in ANGLE
* CVE-2026-4453: Integer overflow in Dawn
* CVE-2026-4454: Use after free in Network
* CVE-2026-4455: Heap buffer overflow in PDFium
* CVE-2026-4456: Use after free in Digital Credentials API
* CVE-2026-4457: Type Confusion in V8
* CVE-2026-4458: Use after free in Extensions
* CVE-2026-4459: Out of bounds read and write in WebAudio
* CVE-2026-4460: Out of bounds read in Skia
* CVE-2026-4461: Inappropriate implementation in V8
* CVE-2026-4462: Out of bounds read in Blink
* CVE-2026-4463: Heap buffer overflow in WebRTC
* CVE-2026-4464: Integer overflow in ANGLE
* CVE-2026-3909: Out of bounds write in Ski
* CVE-2026-3909: Out of bounds write in Skia
* CVE-2026-3910: Inappropriate implementation in V8
* CVE-2026-3913: Heap buffer overflow in WebML
* CVE-2026-3914: Integer overflow in WebML
* CVE-2026-3915: Heap buffer overflow in WebML
* CVE-2026-3916: Out of bounds read in Web Speech
* CVE-2026-3917: Use after free in Agents
* CVE-2026-3909: Out of bounds write in Skia
* CVE-2026-3910: Inappropriate implementation in V8
* CVE-2026-3913: Heap buffer overflow in WebML
* CVE-2026-3914: Integer overflow in WebML
* CVE-2026-3915: Heap buffer overflow in WebML
* CVE-2026-3916: Out of bounds read in Web Speech
* CVE-2026-3917: Use after free in Agents
* CVE-2026-3918: Use after free in WebMCP
* CVE-2026-3919: Use after free in Extensions
* CVE-2026-3920: Out of bounds memory access in WebML
* CVE-2026-3921: Use after free in TextEncoding
* CVE-2026-3922: Use after free in MediaStream
* CVE-2026-3923: Use after free in WebMIDI
* CVE-2026-3924: Use after free in WindowDialog
* CVE-2026-3925: Incorrect security UI in LookalikeChecks
* CVE-2026-3926: Out of bounds read in V8
* CVE-2026-3927: Incorrect security UI in PictureInPicture
* CVE-2026-3928: Insufficient policy ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cef' package(s) on Fedora 42.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~146.0.9^chromium146.0.7680.164~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~146.0.9^chromium146.0.7680.164~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~146.0.9^chromium146.0.7680.164~1.fc42", rls:"FC42"))) {
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
