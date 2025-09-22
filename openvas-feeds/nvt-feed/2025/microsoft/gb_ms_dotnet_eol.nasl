# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834598");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-28 16:11:50 +0530 (Fri, 28 Mar 2025)");
  script_name("Microsoft .NET End of Life (EOL) Detection");

  script_tag(name:"summary", value:"The Microsoft .NET product on the
  remote host has reached the End of Life (EOL) and should not be used
  anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on
  the target host.");

  script_tag(name:"impact", value:"An EOL version of Microsoft .NET is
  not receiving any security updates from the vendor. Unfixed security
  vulnerabilities might be leveraged by an attacker to compromise the security
  of this host.");

  script_tag(name:"solution", value:"Update to .NET 8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://devblogs.microsoft.com/dotnet/dotnet-7-end-of-support/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}

include("host_details.inc");
include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:FALSE))
  exit(0);

version = infos["version"];
if(!version)
  version = "unknown";

if(ret = product_reached_eol(cpe:CPE, version:version)) {
  report = eol_build_message(name:"Microsoft .NET",
                             cpe:CPE,
                             version:version,
                             location:infos["location"],
                             eol_version:ret["eol_version"],
                             eol_date:ret["eol_date"],
                             eol_type:"prod");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
