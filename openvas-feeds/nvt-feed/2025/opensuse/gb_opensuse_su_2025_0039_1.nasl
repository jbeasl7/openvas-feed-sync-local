# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0039.1");
  script_cve_id("CVE-2019-13217", "CVE-2019-13218", "CVE-2019-13219", "CVE-2019-13220", "CVE-2019-13221", "CVE-2019-13222", "CVE-2019-13223");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-20 19:45:33 +0000 (Tue, 20 Aug 2019)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0039-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0039-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PZDT6XNDTXL5IKK6DIS36QIONKMQA3A4/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216478");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stb' package(s) announced via the openSUSE-SU-2025:0039-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for stb fixes the following issues:

Addressing the follow security issues (boo#1216478):

* CVE-2019-13217: heap buffer overflow in start_decoder()
* CVE-2019-13218: stack buffer overflow in compute_codewords()
* CVE-2019-13219: uninitialized memory in vorbis_decode_packet_rest()
* CVE-2019-13220: out-of-range read in draw_line()
* CVE-2019-13221: issue with large 1D codebooks in lookup1_values()
* CVE-2019-13222: unchecked NULL returned by get_window()
* CVE-2019-13223: division by zero in predict_point()");

  script_tag(name:"affected", value:"'stb' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"stb-devel", rpm:"stb-devel~20240910~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
