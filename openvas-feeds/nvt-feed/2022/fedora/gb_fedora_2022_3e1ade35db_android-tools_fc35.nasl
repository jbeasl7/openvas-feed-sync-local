# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821586");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-07-21 01:11:32 +0000 (Thu, 21 Jul 2022)");
  script_name("Fedora: Security Advisory for android-tools (FEDORA-2022-3e1ade35db)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-3e1ade35db");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MFQMDQPNFIR4EAQGJML5AWMHNBLKECHB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'android-tools'
  package(s) announced via the FEDORA-2022-3e1ade35db advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Android Debug Bridge (ADB) is used to:

  - keep track of all Android devices and emulators instances
  connected to or running on a given host developer machine

  - implement various control commands (e.g. 'adb shell', 'adb pull',
etc.)
  for the benefit of clients (command-line users, or helper programs like
  DDMS). These commands are what is called a &#39, service&#39, in ADB.

Fastboot is used to manipulate the flash partitions of the Android phone.
It can also boot the phone using a kernel image or root filesystem image
which reside on the host machine rather than in the phone flash.
In order to use it, it is important to understand the flash partition
layout for the phone.
The fastboot program works in conjunction with firmware on the phone
to read and write the flash partitions. It needs the same USB device
setup between the host and the target phone as adb.");

  script_tag(name:"affected", value:"'android-tools' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"android-tools", rpm:"android-tools~31.0.2~2.fc35", rls:"FC35"))) {
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
