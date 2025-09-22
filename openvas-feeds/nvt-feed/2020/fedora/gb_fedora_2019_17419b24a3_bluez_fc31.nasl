# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.877290");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-01-09 07:36:14 +0000 (Thu, 09 Jan 2020)");
  script_name("Fedora Update for bluez FEDORA-2019-17419b24a3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2019-17419b24a3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RLZUCXXSKY5T73XN3MMNBCFSJ7XJ44VH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez'
  package(s) announced via the FEDORA-2019-17419b24a3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Utilities for use in Bluetooth applications:

  - hcitool

  - hciattach

  - hciconfig

  - bluetoothd

  - l2ping

  - rfcomm

  - sdptool

  - bccmd

  - bluetoothctl

  - btmon

  - hcidump

  - l2test

  - rctest

  - gatttool

  - start scripts (Red Hat)

  - pcmcia configuration files

  - avinfo

The BLUETOOTH trademarks are owned by Bluetooth SIG, Inc., U.S.A.");

  script_tag(name:"affected", value:"'bluez' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.52~1.fc31", rls:"FC31"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
