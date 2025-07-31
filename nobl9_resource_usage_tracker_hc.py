#!/usr/bin/env python3
"""
Nobl9 Resource Usage Tracker (Hardcoded Credentials Version).

This script fetches resource usage data from the Nobl9 Reports API and appends it
to a CSV file for tracking usage over time. This version uses hardcoded credentials
for automation and CI/CD pipelines.

Usage:
    python nobl9_resource_usage_tracker_hc.py [--csv-file CSV_FILE]

Dependencies:
    pip install requests
"""

# =============================================================================
# USER CONFIGURATION - MODIFY THESE VALUES
# =============================================================================

# Nobl9 API Credentials
CLIENT_ID = "your-client-id-here"
CLIENT_SECRET = "your-client-secret-here"
ORGANIZATION_ID = "your-organization-id-here"

# Custom Instance Configuration (optional)
# Set to True if using a custom Nobl9 instance
IS_CUSTOM_INSTANCE = False
# Set to your custom base URL if using a custom instance
# Example: "https://us1.nobl9.com/api"
CUSTOM_BASE_URL = None

# Okta Configuration (for custom instances with Okta authentication)
# Set to your Okta organization URL if using Okta authentication
# Example: "https://accounts-us1.nobl9.com"
OKTA_ORG_URL = None
# Set to your Okta authorization server if using Okta authentication
# Example: "xxxxx506kj9Jxxx3g4x6"
OKTA_AUTH_SERVER = None

# =============================================================================
# END USER CONFIGURATION
# =============================================================================

import argparse
import base64
import csv
import json
import os
import re
import sys
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

try:
    import requests
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install requests")
    sys.exit(1)


def decode_jwt_payload(token: str) -> Optional[str]:
    """Decode JWT token to extract organization info."""
    try:
        # JWT has three parts: header.payload.signature
        payload_b64 = token.split('.')[1]
        # Add padding if necessary
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        # Look for organization in m2mProfile
        return payload.get('m2mProfile', {}).get('organization', None)
    except Exception:
        return None


def authenticate() -> Tuple[str, str]:
    """Authenticate with Nobl9 API using hardcoded credentials."""
    if not CLIENT_ID or CLIENT_ID == "your-client-id-here":
        print("ERROR: Please set CLIENT_ID in the configuration section at the "
              "top of the script.")
        sys.exit(1)
    
    if not CLIENT_SECRET or CLIENT_SECRET == "your-client-secret-here":
        print("ERROR: Please set CLIENT_SECRET in the configuration section at "
              "the top of the script.")
        sys.exit(1)
    
    if not ORGANIZATION_ID or ORGANIZATION_ID == "your-organization-id-here":
        print("ERROR: Please set ORGANIZATION_ID in the configuration section at "
              "the top of the script.")
        sys.exit(1)
    
    encoded_creds = base64.b64encode(
        f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    ).decode()
    
    headers = {
        "Authorization": f"Basic {encoded_creds}",
        "Content-Type": "application/json",
        "Organization": ORGANIZATION_ID
    }
    
    # Determine authentication URL
    if IS_CUSTOM_INSTANCE and CUSTOM_BASE_URL:
        print(f"Using custom instance: {CUSTOM_BASE_URL}")
        auth_url = f"{CUSTOM_BASE_URL}/accessToken"
    else:
        auth_url = "https://app.nobl9.com/api/accessToken"
    
    try:
        response = requests.post(auth_url, headers=headers, timeout=30)
        if response.status_code != 200:
            print("ERROR: Authentication failed")
            _handle_auth_error(response)
            sys.exit(1)
        
        token_data = response.json()
        token = token_data.get("access_token")
        if not token:
            print("ERROR: No access token in response")
            print(f"  Response: {response.text}")
            sys.exit(1)
        return token, ORGANIZATION_ID
        
    except requests.exceptions.Timeout:
        print("ERROR: Authentication request timed out")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error during authentication: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON response from authentication endpoint")
        print(f"  Response: {response.text}")
        sys.exit(1)


def _handle_auth_error(response: requests.Response) -> None:
    """Handle authentication error responses."""
    try:
        error_data = response.json()
        if "error" in error_data:
            error_info = error_data["error"]
            if isinstance(error_info, str):
                try:
                    json_match = re.search(r'\{.*\}', error_info)
                    if json_match:
                        nested_error = json.loads(json_match.group())
                        print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                        print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                        print(f"  Error ID: {nested_error.get('errorId', 'No ID provided')}")
                        if nested_error.get('errorCauses'):
                            print(f"  Causes: {nested_error['errorCauses']}")
                    else:
                        print(f"  Error: {error_info}")
                except json.JSONDecodeError:
                    print(f"  Error: {error_info}")
            else:
                print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                print(f"  Error ID: {error_info.get('errorId', 'No ID provided')}")
                if error_info.get('errorCauses'):
                    print(f"  Causes: {error_info['errorCauses']}")
        elif "message" in error_data:
            print(f"  Message: {error_data['message']}")
        else:
            print(f"  Response: {response.text}")
    except json.JSONDecodeError:
        print(f"  Raw response: {response.text}")


def fetch_resource_usage(token: str, org: str) -> Dict[str, Any]:
    """Fetch resource usage summary from Nobl9 Reports API."""
    # Determine API base URL
    if IS_CUSTOM_INSTANCE and CUSTOM_BASE_URL:
        api_base_url = f"{CUSTOM_BASE_URL}/reports/v1/usage-summary"
    else:
        api_base_url = "https://app.nobl9.com/api/reports/v1/usage-summary"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Organization": org,
        "Accept": "application/json; version=v1alpha"
    }
    
    try:
        response = requests.get(api_base_url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"ERROR: Failed to fetch resource usage (Status: {response.status_code})")
            _handle_api_error(response)
            sys.exit(1)
        
        # DEBUG: Uncomment the lines below to see the full API response JSON
        # This is useful for debugging API responses, understanding data structure,
        # or troubleshooting tier/usage information.
        #
        # print("\n" + "="*60)
        # print("DEBUG: Full API Response JSON")
        # print("="*60)
        # print(json.dumps(response.json(), indent=2))
        # print("="*60)
        # print("DEBUG: End of API Response")
        # print("="*60 + "\n")
        
        return response.json()
        
    except requests.exceptions.Timeout:
        print("ERROR: API request timed out")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error during API request: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to fetch resource usage: {e}")
        sys.exit(1)


def _handle_api_error(response: requests.Response) -> None:
    """Handle API error responses."""
    try:
        error_data = response.json()
        if "error" in error_data:
            error_info = error_data["error"]
            if isinstance(error_info, str):
                try:
                    json_match = re.search(r'\{.*\}', error_info)
                    if json_match:
                        nested_error = json.loads(json_match.group())
                        print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                        print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                        print(f"  Error ID: {nested_error.get('errorId', 'No ID provided')}")
                    else:
                        print(f"  Error: {error_info}")
                except json.JSONDecodeError:
                    print(f"  Error: {error_info}")
            else:
                print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                print(f"  Error ID: {error_info.get('errorId', 'No ID provided')}")
        elif "message" in error_data:
            print(f"  Message: {error_data['message']}")
        else:
            print(f"  Response: {response.text}")
    except json.JSONDecodeError:
        print(f"  Raw response: {response.text}")


def append_to_csv(data: Dict[str, Any], csv_file: str, org: str) -> None:
    """Append resource usage data to CSV file."""
    timestamp = datetime.now().isoformat()
    
    # Extract usage data
    usage_summary = data.get("usageSummary", {})
    metadata = data.get("metadata", {})
    
    # Prepare row data
    row = {
        "timestamp": timestamp,
        "organization": org,
        "tier": metadata.get("tier", {}).get("name", ""),
        "generated_at": metadata.get("generatedAt", ""),
        "license_end_date": metadata.get("licenseEndDate", ""),
        
        # SLOs
        "slos_current": usage_summary.get("slos", {}).get("currentUsage", 0),
        "slos_peak": usage_summary.get("slos", {}).get("peakUsage", 0),
        
        # SLO Units
        "slo_units_current": usage_summary.get("sloUnits", {}).get("currentUsage", 0),
        "slo_units_peak": usage_summary.get("sloUnits", {}).get("peakUsage", 0),
        
        # Composite SLO Components
        "composite_slo_current": usage_summary.get("compositeSloComponents", {}).get("currentUsage", 0),
        "composite_slo_peak": usage_summary.get("compositeSloComponents", {}).get("peakUsage", 0),
        
        # Data Sources
        "data_sources_current": usage_summary.get("dataSources", {}).get("currentUsage", 0),
        "data_sources_peak": usage_summary.get("dataSources", {}).get("peakUsage", 0),
        
        # Users
        "users_current": usage_summary.get("users", {}).get("currentUsage", 0),
        "users_peak": usage_summary.get("users", {}).get("peakUsage", 0)
    }
    
    # Check if file exists to determine if we need to write headers
    file_exists = os.path.exists(csv_file)
    
    # Write to CSV
    with open(csv_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(row)
    
    print(f"SUCCESS: Data appended to {csv_file}")


def display_usage_summary(data: Dict[str, Any]) -> None:
    """Display a summary of the resource usage data."""
    usage_summary = data.get("usageSummary", {})
    
    print("\nUsage Details:")
    print("   Format: Current Usage / Peak Usage")
    print()
    
    # SLOs
    slos = usage_summary.get("slos", {})
    current_slos = slos.get('currentUsage', 0)
    peak_slos = slos.get('peakUsage', 0)
    print(f"   SLOs:           {current_slos:>3} / {peak_slos}")
    
    # SLO Units
    slo_units = usage_summary.get("sloUnits", {})
    current_units = slo_units.get('currentUsage', 0)
    peak_units = slo_units.get('peakUsage', 0)
    print(f"   SLO Units:      {current_units:>3} / {peak_units}")
    
    # Composite SLO Components
    composite_slo = usage_summary.get("compositeSloComponents", {})
    current_composite = composite_slo.get('currentUsage', 0)
    peak_composite = composite_slo.get('peakUsage', 0)
    print(f"   Composite SLOs: {current_composite:>3} / {peak_composite}")
    
    # Data Sources
    data_sources = usage_summary.get("dataSources", {})
    current_ds = data_sources.get('currentUsage', 0)
    peak_ds = data_sources.get('peakUsage', 0)
    print(f"   Data Sources:   {current_ds:>3} / {peak_ds}")
    
    # Users
    users = usage_summary.get("users", {})
    current_users = users.get('currentUsage', 0)
    peak_users = users.get('peakUsage', 0)
    print(f"   Users:          {current_users:>3} / {peak_users}")


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Track Nobl9 resource usage and append to CSV file "
                   "(Hardcoded Credentials)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nobl9_resource_usage_tracker_hc.py
  python nobl9_resource_usage_tracker_hc.py --csv-file usage_tracking.csv

        Note: Make sure to set your credentials in the configuration section at "
              "the top of the script.
        """
    )
    
    parser.add_argument(
        "--csv-file",
        help="CSV file to append data to "
             "(default: nobl9_resource_usage_{org}.csv)"
    )
    
    args = parser.parse_args()
    
    print("Nobl9 Resource Usage Tracker (Hardcoded Credentials)")
    print("=" * 55)
    
    # Authenticate
    print("Authenticating...")
    token, org = authenticate()
    
    print("SUCCESS: Successfully authenticated with Nobl9")
    
    # Determine CSV filename
    if args.csv_file:
        csv_filename = args.csv_file
    else:
        # Use organization name in default filename
        csv_filename = f"nobl9_resource_usage_{org}.csv"
    
    # Fetch resource usage
    print("Fetching resource usage data...")
    usage_data = fetch_resource_usage(token, org)
    
    # Display summary
    display_usage_summary(usage_data)
    
    # Append to CSV
    append_to_csv(usage_data, csv_filename, org)


if __name__ == "__main__":
    main() 