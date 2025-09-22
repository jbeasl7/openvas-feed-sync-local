# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1918");
  script_cve_id("CVE-2025-1215", "CVE-2025-26603", "CVE-2025-29768");
  script_tag(name:"creation_date", value:"2025-09-03 14:51:03 +0000 (Wed, 03 Sep 2025)");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-13 17:28:19 +0000 (Wed, 13 Aug 2025)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2025-1918)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1918");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1918");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2025-1918 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vim is a greatly improved version of the good old UNIX editor Vi. Vim allows to redirect screen messages using the `:redir` ex command to register, variables and files. It also allows to show the contents of registers using the `:registers` or `:display` ex command. When redirecting the output of `:display` to a register, Vim will free the register content before storing the new content in the register. Now when redirecting the `:display` command to a register that is being displayed, Vim will free the content while shortly afterwards trying to access it, which leads to a use-after-free. Vim pre 9.1.1115 checks in the ex_display() function, that it does not try to redirect to a register while displaying this register at the same time. However this check is not complete, and so Vim does not check the `+` and `*` registers (which typically donate the X11/clipboard registers, and when a clipboard connection is not possible will fall back to use register 0 instead. In Patch 9.1.1115 Vim will therefore skip outputting to register zero when trying to redirect to the clipboard registers `*` or `+`. Users are advised to upgrade. There are no known workarounds for this vulnerability.(CVE-2025-26603)

A vulnerability classified as problematic was found in vim up to 9.1.1096. This vulnerability affects unknown code of the file src/main.c. The manipulation of the argument --log leads to memory corruption. It is possible to launch the attack on the local host. Upgrading to version 9.1.1097 is able to address this issue. The patch is identified as c5654b84480822817bb7b69ebc97c174c91185e9. It is recommended to upgrade the affected component.(CVE-2025-1215)

Vim, a text editor, is vulnerable to potential data loss with zip.vim and special crafted zip files in versions prior to 9.1.1198. The impact is medium because a user must be made to view such an archive with Vim and then press 'x' on such a strange filename. The issue has been fixed as of Vim patch v9.1.1198.(CVE-2025-29768)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS Virtualization release 2.12.0.");

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

if(release == "EULEROSVIRT-2.12.0") {

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0~5.h22.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0~5.h22.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~9.0~5.h22.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0~5.h22.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
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
