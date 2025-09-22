# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0334");
  script_cve_id("CVE-2024-7519", "CVE-2024-7520", "CVE-2024-7521", "CVE-2024-7522", "CVE-2024-7524", "CVE-2024-7525", "CVE-2024-7526", "CVE-2024-7527", "CVE-2024-7528", "CVE-2024-7529", "CVE-2024-8381", "CVE-2024-8382", "CVE-2024-8383", "CVE-2024-8384", "CVE-2024-8385", "CVE-2024-8386", "CVE-2024-8387", "CVE-2024-9680");
  script_tag(name:"creation_date", value:"2024-10-25 04:13:01 +0000 (Fri, 25 Oct 2024)");
  script_version("2024-10-25T15:39:56+0000");
  script_tag(name:"last_modification", value:"2024-10-25 15:39:56 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 15:07:36 +0000 (Wed, 16 Oct 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0334)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0334");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0334.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33607");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the MGASA-2024-0334 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package provides Firefox 128 for all mandatory arches of
Mageia (x86_64, i586 and aarch64), fixing several bugs, including
security vulnerabilities, for i586 and aarch64:
Fullscreen notification dialog can be obscured by document content.
(CVE-2024-7518)
Out of bounds memory access in graphics shared memory handling.
(CVE-2024-7519)
Type confusion in WebAssembly. (CVE-2024-7520)
Incomplete WebAssembly exception handing. (CVE-2024-7521)
Out of bounds read in editor component. (CVE-2024-7522)
CSP strict-dynamic bypass using web-compatibility shims. (CVE-2024-7524)
Missing permission check when creating a StreamFilter. (CVE-2024-7525)
Uninitialized memory used by WebGL. (CVE-2024-7526)
Use-after-free in JavaScript garbage collection. (CVE-2024-7527)
Use-after-free in IndexedDB. (CVE-2024-7528)
Document content could partially obscure security prompts.
(CVE-2024-7529)
WASM type confusion involving ArrayTypes. (CVE-2024-8385)
Type confusion when looking up a property name in a 'with' block.
(CVE-2024-8381)
Internal event interfaces were exposed to web content when browser
EventHandler listener callbacks ran. (CVE-2024-8382)
links in an external application. (CVE-2024-8383: Firefox did not ask
before openings news)
Garbage collection could mis-color cross-compartment objects in OOM
conditions. (CVE-2024-8384)
SelectElements could be shown over another site if popups are allowed.
(CVE-2024-8386)
Memory safety bugs fixed in Firefox 130, Firefox ESR 128.2, and
Thunderbird 128.2. (CVE-2024-8387)
Compromised content process can bypass site isolation. (CVE-2024-9392)
Cross-origin access to PDF contents through multipart responses.
(CVE-2024-9393)
Cross-origin access to JSON contents through multipart responses.
(CVE-2024-9394)
Clipboard write permission bypass. (CVE-2024-8900)
Potential memory corruption may occur when cloning certain objects.
(CVE-2024-9396)
Potential directory upload bypass via clickjacking. (CVE-2024-9397)
External protocol handlers could be enumerated via popups.
(CVE-2024-9398)
Specially crafted WebTransport requests could lead to denial of service.
(CVE-2024-9399)
Potential memory corruption during JIT compilation. (CVE-2024-9400)
Memory safety bugs fixed in Firefox 131, Firefox ESR 115.16, Firefox ESR
128.3, Thunderbird 131, and Thunderbird 128.3. (CVE-2024-9401)
Memory safety bugs fixed in Firefox 131, Firefox ESR 128.3, Thunderbird
131, and Thunderbird 128.3. (CVE-2024-9402)
Use-after-free in Animation timeline. (CVE-2024-9680)");

  script_tag(name:"affected", value:"'firefox' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~128.3.1~3.mga9", rls:"MAGEIA9"))) {
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
