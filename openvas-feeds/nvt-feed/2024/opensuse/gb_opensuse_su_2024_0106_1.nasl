# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856067");
  script_cve_id("CVE-2024-3119", "CVE-2024-3120");
  script_tag(name:"creation_date", value:"2024-04-15 06:35:04 +0000 (Mon, 15 Apr 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-03 17:44:43 +0000 (Mon, 03 Feb 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0106-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XIKQJYLNI5D5D5THR2I23E2KMGZKXH46/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sngrep' package(s) announced via the openSUSE-SU-2024:0106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sngrep fixes the following issues:

- Update to version 1.8.1
 * Fix CVE-2024-3119: sngrep: buffer overflow due to improper
 handling of 'Call-ID' and 'X-Call-ID' SIP headers.
 * Fix CVE-2024-3120: sngrep: stack-buffer overflow due to
 inadequate bounds checking when copying 'Content-Length' and
 'Warning' headers into fixed-size buffers.

- Update to versino 1.8.0
 * fix typo in message, thanks to lintian.
 * fix compiler warnings about unused variables.
 * Fixed a typo in comment line in filter.c
 * Redefine usage of POSIX signals.
 * Support for building sngrep using CMake added.

- Update to version 1.7.0
 * save: add option --text to save captured data to plain text
 * capture: fix memory overflows while parsing IP headers
 * hep: fix hep listener enabled in offline mode
 * core: stop sngrep when parent process has ended
 * ssl: fix decrypt with AES256 GCM SHA384 cipher");

  script_tag(name:"affected", value:"'sngrep' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sngrep", rpm:"sngrep~1.8.1~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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
