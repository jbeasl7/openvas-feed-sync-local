# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0193");
  script_cve_id("CVE-2017-9258", "CVE-2017-9259", "CVE-2017-9260", "CVE-2018-1000223", "CVE-2018-14044", "CVE-2018-14045", "CVE-2018-17096", "CVE-2018-17097", "CVE-2018-17098");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-08 19:28:16 +0000 (Thu, 08 Nov 2018)");

  script_name("Mageia: Security Advisory (MGASA-2020-0193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0193");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0193.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2018-0331.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2018-0385.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2018-0462.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26555");
  script_xref(name:"URL", value:"https://github.com/dolphin-emu/dolphin/pull/8725");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dolphin-emu' package(s) announced via the MGASA-2020-0193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dolphin-emu package fixes security vulnerabilities

Dolphin Emulator includes a modified copy of the SoundTouch library at
version 1.9.2. That version is subject to the following security issues:

- The TDStretch::processSamples function in source/SoundTouch/TDStretch.cpp
 in SoundTouch 1.9.2 allows remote attackers to cause a denial of service
 (infinite loop and CPU consumption) via a crafted wav file (CVE-2017-9258)

- The TDStretch::acceptNewOverlapLength function in source/SoundTouch/
 TDStretch.cpp in SoundTouch 1.9.2 allows remote attackers to cause a
 denial of service (memory allocation error and application crash) via a
 crafted wav file (CVE-2017-9259).

- The TDStretchSSE::calcCrossCorr function in source/SoundTouch/
 sse_optimized.cpp in SoundTouch 1.9.2 allows remote attackers to cause a
 denial of service (heap-based buffer over-read and application crash) via
 a crafted wav file (CVE-2017-9260).

- Reachable assertion in RateTransposer::setChannels() causing denial of
 service (CVE-2018-14044).

- Reachable assertion in FIRFilter.cpp causing denial of service
 (CVE-2018-14045).

- Assertion failure in BPMDetect class in BPMDetect.cpp (CVE-2018-17096).

- Out-of-bounds heap write in WavOutFile::write() (CVE-2018-17097).

- Heap corruption in WavFileBase class in WavFile.cpp (CVE-2018-17098).

- Heap-based buffer overflow in SoundStretch/WavFile.cpp:WavInFile
 ::readHeaderBlock() potentially leading to code execution
 (CVE-2018-1000223).

The bundled copy of SoundTouch was updated to version 2.1.2, thereby solving
these, thesis issues in Dolphin Emulator.");

  script_tag(name:"affected", value:"'dolphin-emu' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dolphin-emu", rpm:"dolphin-emu~5.0.11824~1.mga7.tainted", rls:"MAGEIA7"))) {
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
