# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833382");
  script_cve_id("CVE-2024-25442", "CVE-2024-25443", "CVE-2024-25445", "CVE-2024-25446");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:00 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 04:42:32 +0000 (Thu, 15 Feb 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0047-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/L2F34UEYXKH5DPAK35YKK7INNA4FS6WN/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219822");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hugin' package(s) announced via the openSUSE-SU-2024:0047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hugin fixes the following issues:

Update to version 2023.0.0:

 * PTBatcherGUI can now also queue user defined assistant and
 user defined output sequences.
 * PTBatcherGUI: Added option to generate panorama sequences from
 an existing pto template.
 * Assistant: Added option to select different output options
 like projection, FOV or canvas size depending on different
 variables (e.g. image count, field of view, lens type).
 * Allow building with epoxy instead of GLEW for OpenGL pointer
 management.
 * Several improvements to crop tool (outside crop, aspect ratio,
 ...).
 * Several bug fixes (e.g. in verdandi/internal blender).
 * Updated translations.
- fixed: boo#1219819 (CVE-2024-25442), boo#1219820 (CVE-2024-25443)
 boo#1219821 (CVE-2024-25445), boo#1219822 (CVE-2024-25446)");

  script_tag(name:"affected", value:"'hugin' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"hugin", rpm:"hugin~2023.0.0~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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
