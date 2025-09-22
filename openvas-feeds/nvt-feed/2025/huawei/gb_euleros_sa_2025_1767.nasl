# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1767");
  script_cve_id("CVE-2025-1215", "CVE-2025-22134", "CVE-2025-24014");
  script_tag(name:"creation_date", value:"2025-08-06 04:43:07 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-13 17:28:19 +0000 (Wed, 13 Aug 2025)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2025-1767)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.13\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1767");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1767");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2025-1767 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability classified as problematic was found in vim up to 9.1.1096. This vulnerability affects unknown code of the file src/main.c. The manipulation of the argument --log leads to memory corruption. It is possible to launch the attack on the local host. Upgrading to version 9.1.1097 is able to address this issue. The patch is identified as c5654b84480822817bb7b69ebc97c174c91185e9. It is recommended to upgrade the affected component.(CVE-2025-1215)

Vim is an open source, command line text editor. A segmentation fault was found in Vim before 9.1.1043. In silent Ex mode (-s -e), Vim typically doesn't show a screen and just operates silently in batch mode. However, it is still possible to trigger the function that handles the scrolling of a gui version of Vim by feeding some binary characters to Vim. The function that handles the scrolling however may be triggering a redraw, which will access the ScreenLines pointer, even so this variable hasn't been allocated (since there is no screen). This vulnerability is fixed in 9.1.1043.(CVE-2025-24014)

When switching to other buffers using the :all command and visual mode still being active, this may cause a heap-buffer overflow, because Vim does not properly end visual mode and therefore may try to access beyond the end of a line in a buffer. In Patch 9.1.1003 Vim will correctly reset the visual mode before opening other windows and buffers and therefore fix this bug. In addition it does verify that it won't try to access a position if the position is greater than the corresponding buffer line. Impact is medium since the user must have switched on visual mode when executing the :all ex command. The Vim project would like to thank github user gandalf4a for reporting this issue. The issue has been fixed as of Vim patch v9.1.1003(CVE-2025-22134)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization release 2.13.0.");

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

if(release == "EULEROSVIRT-2.13.0") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0~23.h9.eulerosv2r13", rls:"EULEROSVIRT-2.13.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0~23.h9.eulerosv2r13", rls:"EULEROSVIRT-2.13.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~9.0~23.h9.eulerosv2r13", rls:"EULEROSVIRT-2.13.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0~23.h9.eulerosv2r13", rls:"EULEROSVIRT-2.13.0"))) {
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
