# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113728");
  script_version("2021-07-22T11:01:40+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-07-22 09:34:04 +0000 (Wed, 22 Jul 2020)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-11 06:15:00 +0000 (Wed, 11 Nov 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-13361", "CVE-2020-13362", "CVE-2020-16092");

  script_name("QEMU <= 5.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_qemu_detect_lin.nasl");
  script_mandatory_keys("QEMU/Lin/Ver");

  script_tag(name:"summary", value:"QEMU is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - es1370_transfer_audio in hw/audio/es1370.c does not properly validate the frame count,
    which allows guest OS users to trigger an out-of-bounds access during an es1370_write() operation. (CVE-2020-13361)

  - megasas_lookup_frame in hw/scsi/megasas.c has an out-of-bounds read
    via a crafted reply_queue_head field from a guest OS user. (CVE-2020-13362)

  - There is a denial of service condition in net_tx_pkt_add_raw_fragment in hw/net/net_tx_pkt.c
    due to an assertion failure that can occur during network packet processing. (CVE-2020-16092)");

  script_tag(name:"affected", value:"QEMU through version 5.0.0.");

  script_tag(name:"solution", value:"Update to version 5.1.0.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/05/28/1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/05/28/2");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/08/10/1");

  exit(0);
}

CPE = "cpe:/a:qemu:qemu";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
